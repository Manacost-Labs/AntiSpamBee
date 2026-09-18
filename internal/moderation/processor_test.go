package moderation

import (
	"context"
	"errors"
	"testing"

	"antispambee/internal/detection"
	"antispambee/internal/events"
)

type recordingStore struct {
	event   events.TelegramUpdate
	outcome Outcome
	err     error
}

func hasAction(outcome Outcome, actionType ActionType) bool {
	for _, action := range outcome.Actions {
		if action.Type == actionType {
			return true
		}
	}
	return false
}

func TestActionRequestsForBanDeleteMessageBeforeUserBan(t *testing.T) {
	target := ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7}

	actions := actionRequestsFor("event-1", ActionBanUser, target)

	if len(actions) != 2 {
		t.Fatalf("actions = %#v, want delete and ban", actions)
	}
	if actions[0].Type != ActionDeleteMessage || actions[1].Type != ActionBanUser {
		t.Fatalf("action order = %q/%q, want DELETE_MESSAGE/BAN_USER", actions[0].Type, actions[1].Type)
	}
	if actions[0].IdempotencyKey == actions[1].IdempotencyKey {
		t.Fatal("delete and ban idempotency keys must differ")
	}
}

func (s *recordingStore) RecordTerminal(_ context.Context, event events.TelegramUpdate, outcome Outcome) error {
	s.event = event
	s.outcome = outcome
	return s.err
}

type profileFetcherStub struct {
	profile      detection.Profile
	err          error
	userID       int64
	calls        int
	memberStatus string
	memberErr    error
}

type semanticAdStub struct {
	signal  detection.Signal
	content detection.SemanticAdContent
}

func (s *semanticAdStub) AnalyzeAdvertising(_ context.Context, content detection.SemanticAdContent) detection.Signal {
	s.content = content
	return s.signal
}

func (f *profileFetcherStub) FetchProfile(_ context.Context, userID int64) (detection.Profile, error) {
	f.calls++
	f.userID = userID
	return f.profile, f.err
}

func (f *profileFetcherStub) GetChatMemberStatus(_ context.Context, _, _ int64) (string, error) {
	if f.memberStatus == "" {
		return "member", f.memberErr
	}
	return f.memberStatus, f.memberErr
}

func TestProcessorRecordsReviewForProfileJobSpam(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{
		PersonalChannel: &detection.PersonalChannel{
			Description: "Нужны сотрудники на частичную занятость. Пишите в личку.",
		},
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{"message":{"from":{"id":8373323792,"is_bot":false,"first_name":"Kristina"},"text":"Спасибо"}}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if fetcher.userID != 8373323792 {
		t.Errorf("fetched user ID = %d", fetcher.userID)
	}
	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	if profileSignal.Score == nil || *profileSignal.Score < 0.9 {
		t.Fatalf("profile score = %v, want at least 0.9", profileSignal.Score)
	}
}

func TestProcessorRecordsAllowWithoutPersonalChannel(t *testing.T) {
	store := &recordingStore{}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{profile: detection.Profile{Username: "ordinary_user"}},
		detection.NewProfileDetector(),
	)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	if err := processor.Process(context.Background(), telegramEvent(`{"message":{"from":{"id":42}}}`)); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedAllow {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedAllow)
	}
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	if profileSignal.Status != detection.StatusMissing {
		t.Fatalf("profile status = %q, want MISSING", profileSignal.Status)
	}
}

func TestProcessorRecordsReviewForAdultPersonalChannel(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{
		PersonalChannel: &detection.PersonalChannel{
			Description: "Приватный контент 18+. Нюдсы и интимные фото.",
		},
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	if err := processor.Process(context.Background(), telegramEvent(`{"message":{"from":{"id":42}}}`)); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
	foundAdultReason := false
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	for _, reason := range profileSignal.ReasonCodes {
		if reason == detection.ReasonAdultContent {
			foundAdultReason = true
		}
	}
	if !foundAdultReason {
		t.Errorf("reason codes = %v, want %q", profileSignal.ReasonCodes, detection.ReasonAdultContent)
	}
}

func TestProcessorRecordsReviewForVPNAdvertisementInMessage(t *testing.T) {
	store := &recordingStore{}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{profile: detection.Profile{Username: "ordinary_user"}},
		detection.NewProfileDetector(),
	)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"from": {"id": 42},
			"text": "NordVPN — Бесплатный VPN. Зачем платить 500 ₽? Установи сейчас",
			"entities": [{"type": "text_link", "offset": 0, "length": 7, "url": "https://example.test/vpn"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
	messageSignal := signalByDetector(t, store.outcome, "message.commercial_promotion")
	if messageSignal.Score == nil || *messageSignal.Score < 0.9 {
		t.Fatalf("message score = %v, want at least 0.9", messageSignal.Score)
	}
}

func TestProcessorRecordsJevSignalInShadowMode(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Bio: "Личный блог"}}
	score := 0.97
	confidence := 0.91
	semantic := &semanticAdStub{signal: detection.Signal{
		SchemaVersion:   "1",
		Detector:        "model.jev_advertising",
		DetectorVersion: "jev-openrouter-v1",
		Category:        "spam.advertising",
		Status:          detection.StatusAvailable,
		Score:           &score,
		Confidence:      &confidence,
		Severity:        detection.SeverityHigh,
		ReasonCodes:     []string{detection.ReasonCommercialPromotion},
		MatchedRules:    []string{"JEV_PROHIBITED_AD_01"},
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector(), WithSemanticAnalyzer(semantic))
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Посмотрите мой новый проект"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedAllow {
		t.Fatalf("terminal state = %q, want shadow ALLOW", store.outcome.State)
	}
	jevSignal := signalByDetector(t, store.outcome, "model.jev_advertising")
	if jevSignal.Score == nil || *jevSignal.Score != 0.97 {
		t.Fatalf("Jev score = %v", jevSignal.Score)
	}
	if semantic.content.Profile.Bio != "Личный блог" || semantic.content.Message.Text != "Посмотрите мой новый проект" {
		t.Fatalf("semantic content = %#v", semantic.content)
	}
}

func TestProcessorChecksProfileOfUserWhoAddsReaction(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{
		PersonalChannel: &detection.PersonalChannel{
			Title:       "Бонусы казино",
			Description: "Казино: бонус за депозит — забрать по ссылке t.me/win",
			RecentPosts: []string{"Регистрируйся и получи бонус"},
		},
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message_reaction": {
			"chat": {"id": -100123, "type": "supergroup"},
			"message_id": 77,
			"user": {"id": 8373323792, "is_bot": false, "first_name": "Kristina"},
			"old_reaction": [],
			"new_reaction": [{"type": "emoji", "emoji": "🔥"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if fetcher.userID != 8373323792 {
		t.Fatalf("fetched user ID = %d, want 8373323792", fetcher.userID)
	}
	if store.outcome.State != DecidedPendingAction {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, DecidedPendingAction)
	}
	if !hasAction(store.outcome, ActionDeleteReaction) {
		t.Fatalf("actions = %#v, want DELETE_REACTION", store.outcome.Actions)
	}
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	if profileSignal.Score == nil || *profileSignal.Score < 0.9 {
		t.Fatalf("profile score = %v, want at least 0.9", profileSignal.Score)
	}
}

func TestProcessorQueuesMessageDeletionAtHighRisk(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Username: "spammer"}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 91,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Казино: бонус 500% за депозит. Забрать по ссылке",
			"entities": [{"type": "text_link", "offset": 0, "length": 6, "url": "https://example.test"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != DecidedPendingAction {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, DecidedPendingAction)
	}
	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
}

func TestProcessorQueuesCompactJobPromotionDeletion(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Username: "spammer"}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 92,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != DecidedPendingAction {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, DecidedPendingAction)
	}
	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
}

func TestProcessorQueuesExclusiveVPNPromotionDeletionWithBareDomain(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Username: "spammer"}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 93,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "VPN с которым летают все соц сети только у нас vpn.ru"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != DecidedPendingAction {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, DecidedPendingAction)
	}
	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
}

func TestProcessorKeepsHighRiskPrivateMessageForReview(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Username: "spammer"}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"from": {"id": 42},
			"chat": {"id": 42, "type": "private"},
			"text": "Казино: бонус 500% за депозит. Забрать по ссылке",
			"entities": [{"type": "text_link", "offset": 0, "length": 6, "url": "https://example.test"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
}

func TestProcessorKeepsProtectedMemberForReview(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{
		profile: detection.Profile{PersonalChannel: &detection.PersonalChannel{
			Title:       "Работа",
			Description: "Нужны сотрудники на частичную занятость, высокий доход. Пишите в личку",
			RecentPosts: []string{"Ищем людей, заработок без вложений"},
		}},
		memberStatus: "administrator",
	}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 92,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Привет"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if store.outcome.State != ProcessedReview || len(store.outcome.Actions) != 0 {
		t.Fatalf("outcome = %#v, want protected REVIEW", store.outcome)
	}
}

func TestProcessorHandlesInlineCallbackWithoutChat(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{
		Bio: "Казино: бонус за депозит — забрать по ссылке t.me/win",
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	if err := processor.Process(
		context.Background(),
		telegramEvent(`{"callback_query":{"from":{"id":42},"inline_message_id":"inline-1"}}`),
	); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
}

func TestProcessorCannotCheckAnonymousReactionActorProfile(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message_reaction": {
			"chat": {"id": -100123},
			"message_id": 77,
			"actor_chat": {"id": -100456, "type": "channel", "title": "Anonymous"},
			"old_reaction": [],
			"new_reaction": [{"type": "emoji", "emoji": "🔥"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if fetcher.calls != 0 {
		t.Fatalf("profile fetch calls = %d, want 0", fetcher.calls)
	}
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	if profileSignal.Status != detection.StatusMissing {
		t.Fatalf("profile status = %q, want MISSING", profileSignal.Status)
	}
}

func TestMessageContentExtractsCaptionAndHiddenLink(t *testing.T) {
	payload := []byte(`{
		"message": {
			"caption": "Бесплатный VPN — установить сейчас",
			"caption_entities": [{"type": "text_link", "offset": 0, "length": 10, "url": "https://example.test/vpn"}]
		}
	}`)

	content := messageContent(payload)

	if content.Caption != "Бесплатный VPN — установить сейчас" {
		t.Errorf("caption = %q", content.Caption)
	}
	if !content.HasLink {
		t.Error("hidden text link was not detected")
	}
	if len(content.URLs) != 1 || content.URLs[0] != "https://example.test/vpn" {
		t.Fatalf("URLs = %v", content.URLs)
	}
}

func TestProcessorDoesNotRaiseRiskWhenProfileFetchFails(t *testing.T) {
	store := &recordingStore{}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{err: errors.New("Telegram unavailable")},
		detection.NewProfileDetector(),
	)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	if err := processor.Process(context.Background(), telegramEvent(`{"message":{"from":{"id":42}}}`)); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != ProcessedAllow {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedAllow)
	}
	profileSignal := signalByDetector(t, store.outcome, "profile.personal_channel")
	if profileSignal.Status != detection.StatusError {
		t.Fatalf("profile status = %q, want ERROR", profileSignal.Status)
	}
}

func signalByDetector(t *testing.T, outcome Outcome, detector string) detection.Signal {
	t.Helper()
	for _, signal := range outcome.Signals {
		if signal.Detector == detector {
			return signal
		}
	}
	t.Fatalf("detector %q not found in %#v", detector, outcome.Signals)
	return detection.Signal{}
}

func TestProcessorReturnsStorageFailure(t *testing.T) {
	wantErr := errors.New("PostgreSQL unavailable")
	processor, err := NewProcessor(
		&recordingStore{err: wantErr},
		&profileFetcherStub{},
		detection.NewProfileDetector(),
	)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	err = processor.Process(context.Background(), telegramEvent(`{"message":{"from":{"id":42}}}`))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Process() error = %v, want wrapped %v", err, wantErr)
	}
}

func telegramEvent(payload string) events.TelegramUpdate {
	return events.TelegramUpdate{
		SchemaVersion: "1",
		TenantID:      "9d83e552-8910-4c46-b55a-63074078829e",
		EventID:       "82373d0f-5740-5f07-b4e8-02c2f4edd824",
		SourceKey:     "telegram:123456:789",
		BotID:         123456,
		UpdateID:      789,
		Payload:       []byte(payload),
	}
}
