package moderation

import (
	"context"
	"errors"
	"testing"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/telegramapi"
)

type recordingStore struct {
	event   events.TelegramUpdate
	outcome Outcome
	err     error
}

type communityPolicyStub struct {
	policy CommunityPolicy
	err    error
}

func (s *communityPolicyStub) GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error) {
	return s.policy, s.err
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

type imageTextExtractorStub struct {
	text   string
	err    error
	fileID string
	calls  int
}

func (s *imageTextExtractorStub) ExtractText(_ context.Context, fileID string) (string, error) {
	s.calls++
	s.fileID = fileID
	return s.text, s.err
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

func TestProcessorUsesHighConfidenceJevSignalForDeletion(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{profile: detection.Profile{Bio: "Личный блог"}}
	score := 0.97
	confidence := 0.91
	semantic := &semanticAdStub{signal: detection.Signal{
		SchemaVersion:    "1",
		Detector:         "model.jev_advertising",
		DetectorVersion:  "jev-openrouter-v1",
		Category:         "spam.advertising",
		Status:           detection.StatusAvailable,
		Score:            &score,
		Confidence:       &confidence,
		EvidenceCoverage: 1,
		Severity:         detection.SeverityHigh,
		ReasonCodes:      []string{detection.ReasonCommercialPromotion},
		MatchedRules:     []string{"JEV_PROHIBITED_AD_01"},
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector(), WithSemanticAnalyzer(semantic))
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 90,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Посмотрите мой новый проект"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.State != DecidedPendingAction || !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("outcome = %#v, want pending DELETE_MESSAGE", store.outcome)
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
	if store.outcome.State != ProcessedReview {
		t.Fatalf("terminal state = %q, want %q", store.outcome.State, ProcessedReview)
	}
	if len(store.outcome.Actions) != 0 {
		t.Fatalf("actions = %#v, want no action for profile-only evidence", store.outcome.Actions)
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

func TestProcessorCapturesDeletedMessageNotificationForCommunityAdmin(t *testing.T) {
	store := &recordingStore{}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{},
		detection.NewProfileDetector(),
		WithPolicyStore(&communityPolicyStub{policy: CommunityPolicy{
			ProtectionLevel:         "STRICT",
			AutomaticActionsEnabled: true,
			AutobanEnabled:          true,
			ModeratorChatID:         9001,
		}}),
	)
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}

	err = processor.Process(context.Background(), telegramEvent(`{
		"message": {
			"message_id": 91,
			"from": {"id": 42, "username": "spam_account"},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Казино: бонус 500% за депозит. Забрать по ссылке",
			"entities": [{"type": "text_link", "offset": 0, "length": 6, "url": "https://example.test"}]
		}
	}`))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	var deletion ActionRequest
	for _, action := range store.outcome.Actions {
		if action.Type == ActionDeleteMessage {
			deletion = action
			break
		}
	}
	if deletion.Notification.ChatID != 9001 || deletion.Notification.AuthorUsername != "spam_account" ||
		deletion.Notification.Message != "Казино: бонус 500% за депозит. Забрать по ссылке" {
		t.Fatalf("notification = %#v", deletion.Notification)
	}
	if len(deletion.Notification.Reasons) == 0 || deletion.Notification.RiskScore < 0.9 {
		t.Fatalf("notification reasons/risk = %#v", deletion.Notification)
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

func TestProcessorDeletesAdvertisingMessageSentAsChannel(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 94,
			"sender_chat": {"id": -100999, "type": "channel"},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "VPN с которым летают все соц сети только у нас vpn.ru"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
	if fetcher.calls != 0 {
		t.Fatalf("profile fetch calls = %d, want 0 for sender_chat", fetcher.calls)
	}
}

func TestProcessorKeepsAnonymousAdminMessageForReview(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 95,
			"sender_chat": {"id": -100777, "type": "supergroup"},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "VPN с которым летают все соц сети только у нас vpn.ru"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if store.outcome.State != ProcessedReview || len(store.outcome.Actions) != 0 {
		t.Fatalf("outcome = %#v, want protected REVIEW", store.outcome)
	}
	if fetcher.calls != 0 {
		t.Fatalf("profile fetch calls = %d, want 0 for anonymous admin", fetcher.calls)
	}
}

func TestProcessorDeletesAdvertisingChannelPost(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatalf("NewProcessor() error = %v", err)
	}
	event := telegramEvent(`{
		"channel_post": {
			"message_id": 96,
			"chat": {"id": -100777, "type": "channel"},
			"text": "Подпишись на наш канал t.me/best_channel",
			"entities": [{"type": "url", "offset": 23, "length": 25}]
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
	if fetcher.calls != 0 {
		t.Fatalf("profile fetch calls = %d, want 0 for channel_post", fetcher.calls)
	}
	if store.outcome.Input.UpdateKind != "channel_post" || store.outcome.Input.TextLength == 0 || !store.outcome.Input.HasLink {
		t.Fatalf("input features = %#v", store.outcome.Input)
	}
}

func TestProcessorRecordsPrivacySafeFeaturesForImageOnlyMessage(t *testing.T) {
	store := &recordingStore{}
	processor, err := NewProcessor(store, &profileFetcherStub{}, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 97,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"photo": [{"file_id": "small"}, {"file_id": "large"}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}

	if store.outcome.Input.UpdateKind != "message" || store.outcome.Input.TextLength != 0 || store.outcome.Input.HasLink {
		t.Fatalf("input features = %#v", store.outcome.Input)
	}
	if len(store.outcome.Input.MediaTypes) != 1 || store.outcome.Input.MediaTypes[0] != "photo" {
		t.Fatalf("media types = %v, want [photo]", store.outcome.Input.MediaTypes)
	}
	if store.outcome.Input.ContentFingerprint == "" {
		t.Fatal("content fingerprint is empty")
	}
}

func TestProcessorDeletesImageOnlyAdvertisementUsingOCR(t *testing.T) {
	store := &recordingStore{}
	ocr := &imageTextExtractorStub{text: "ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС"}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{},
		detection.NewProfileDetector(),
		WithImageTextExtractor(ocr),
	)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 98,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"photo": [
				{"file_id": "small", "file_size": 100},
				{"file_id": "large", "file_size": 1000}
			]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if ocr.calls != 1 || ocr.fileID != "large" {
		t.Fatalf("OCR calls/file = %d/%q, want 1/large", ocr.calls, ocr.fileID)
	}
	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
	if store.outcome.Input.OCRTextLength == 0 {
		t.Fatal("OCR text length was not recorded")
	}
}

func TestProcessorRetriesImageOnlyMessageWhenOCRFails(t *testing.T) {
	store := &recordingStore{}
	ocr := &imageTextExtractorStub{err: &telegramapi.APIError{ErrorCode: 503, Description: "OCR download unavailable"}}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{},
		detection.NewProfileDetector(),
		WithImageTextExtractor(ocr),
	)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 99,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"photo": [{"file_id": "image", "file_size": 1000}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err == nil {
		t.Fatal("Process() error = nil, want OCR retry")
	}
	if store.event.EventID != "" {
		t.Fatal("terminal outcome recorded before OCR retry")
	}
}

func TestProcessorReviewsImageWhenOCRPermanentlyFails(t *testing.T) {
	store := &recordingStore{}
	ocr := &imageTextExtractorStub{err: errors.New("unsupported image")}
	processor, err := NewProcessor(
		store,
		&profileFetcherStub{},
		detection.NewProfileDetector(),
		WithImageTextExtractor(ocr),
	)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 100,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"photo": [{"file_id": "broken", "file_size": 1000}]
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if store.outcome.State != ProcessedReview || store.outcome.Decision.AuthorizedAction != ActionReview {
		t.Fatalf("outcome = %#v, want REVIEW", store.outcome)
	}
	ocrSignal := signalByDetector(t, store.outcome, "image.ocr")
	if ocrSignal.Status != detection.StatusError {
		t.Fatalf("OCR status = %q, want ERROR", ocrSignal.Status)
	}
}

func TestProcessorRetriesWhenHighRiskMemberStatusIsUnavailable(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{memberErr: errors.New("telegram unavailable")}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 95,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "VPN с которым летают все соц сети только у нас vpn.ru"
		}
	}`)

	if err := processor.Process(context.Background(), event); err == nil {
		t.Fatal("Process() succeeded, want retryable member-status error")
	}
	if store.event.EventID != "" {
		t.Fatal("terminal review must not be recorded before member status is known")
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

func TestMessageContentRecognizesObfuscatedTelegramLink(t *testing.T) {
	content := messageContent([]byte(`{
		"message": {
			"text": "Подпишись t[.]me/example"
		}
	}`))

	if !content.HasLink {
		t.Fatal("HasLink = false, want true for t[.]me")
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

func TestProcessorRetriesOrdinaryMessageWhenProfileFetchTemporarilyFails(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{err: &telegramapi.APIError{
		ErrorCode:   503,
		Description: "upstream unavailable",
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 101,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "Обычное сообщение"
		}
	}`)

	if err := processor.Process(context.Background(), event); err == nil {
		t.Fatal("Process() error = nil, want retryable profile error")
	}
	if store.event.EventID != "" {
		t.Fatal("terminal outcome recorded before transient profile retry")
	}
}

func TestProcessorDeletesTextSpamDespiteTemporaryProfileFailure(t *testing.T) {
	store := &recordingStore{}
	fetcher := &profileFetcherStub{err: &telegramapi.APIError{
		ErrorCode:   503,
		Description: "upstream unavailable",
	}}
	processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 102,
			"from": {"id": 42},
			"chat": {"id": -100777, "type": "supergroup"},
			"text": "ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС"
		}
	}`)

	if err := processor.Process(context.Background(), event); err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("actions = %#v, want DELETE_MESSAGE", store.outcome.Actions)
	}
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
