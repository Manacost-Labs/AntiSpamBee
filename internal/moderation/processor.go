package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/telegramapi"
)

// TerminalState records the durable outcome of moderation processing.
type TerminalState string

const (
	// DecidedPendingAction means the decision and an idempotent action were stored.
	DecidedPendingAction TerminalState = "DECIDED_PENDING_ACTION"
	// ProcessedAllow means no suspicious signal crossed the review threshold.
	ProcessedAllow TerminalState = "PROCESSED_ALLOW"
	// ProcessedReview means the event was detected but no automatic action ran.
	ProcessedReview TerminalState = "PROCESSED_REVIEW"
	// ProcessedAction means a high-risk sender was banned successfully.
	ProcessedAction TerminalState = "PROCESSED_ACTION"
)

// Outcome groups the terminal state and the evidence that produced it.
type Outcome struct {
	State    TerminalState
	Input    InputFeatures
	Signals  []detection.Signal
	Decision Decision
	Actions  []ActionRequest
}

// InputFeatures stores privacy-safe metadata needed to audit missed content.
type InputFeatures struct {
	UpdateKind         string
	TextLength         int
	OCRTextLength      int
	HasLink            bool
	MediaTypes         []string
	ContentFingerprint string
}

// ActionRequest is persisted atomically with its decision and later executed
// by the action worker.
type ActionRequest struct {
	Type           ActionType
	Target         ActionTarget
	IdempotencyKey string
	UntilDate      int64
}

type terminalRecorder interface {
	RecordTerminal(context.Context, events.TelegramUpdate, Outcome) error
}

type telegramClient interface {
	FetchProfile(context.Context, int64) (detection.Profile, error)
	GetChatMemberStatus(context.Context, int64, int64) (string, error)
}

type profileDetector interface {
	Analyze(detection.Profile) detection.Signal
}

type semanticAdAnalyzer interface {
	AnalyzeAdvertising(context.Context, detection.SemanticAdContent) detection.Signal
}

type imageTextExtractor interface {
	ExtractText(context.Context, string) (string, error)
}

type behaviorStore interface {
	ObserveMessage(context.Context, events.TelegramUpdate, ActionTarget, detection.MessageContent) (detection.BehaviorStats, error)
}

type policyStore interface {
	GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error)
}

// ProcessorOption enables optional detectors without widening the core client contracts.
type ProcessorOption func(*Processor) error

func WithSemanticAnalyzer(analyzer semanticAdAnalyzer) ProcessorOption {
	return func(processor *Processor) error {
		if analyzer == nil {
			return fmt.Errorf("semantic ad analyzer must not be nil")
		}
		processor.semantic = analyzer
		return nil
	}
}

func WithImageTextExtractor(extractor imageTextExtractor) ProcessorOption {
	return func(processor *Processor) error {
		if extractor == nil {
			return fmt.Errorf("image text extractor must not be nil")
		}
		processor.imageText = extractor
		return nil
	}
}

func WithBehaviorStore(store behaviorStore) ProcessorOption {
	return func(processor *Processor) error {
		if store == nil {
			return fmt.Errorf("behavior store must not be nil")
		}
		processor.behaviorStore = store
		processor.behavior = detection.NewBehaviorDetector()
		return nil
	}
}

func WithPolicyStore(store policyStore) ProcessorOption {
	return func(processor *Processor) error {
		if store == nil {
			return fmt.Errorf("policy store must not be nil")
		}
		processor.policyStore = store
		return nil
	}
}

// Processor enriches events, evaluates profile risk, and records an outcome.
type Processor struct {
	store         terminalRecorder
	profiles      telegramClient
	detector      profileDetector
	messages      *detection.MessageAdDetector
	imageText     imageTextExtractor
	semantic      semanticAdAnalyzer
	decisions     *DecisionEngine
	behaviorStore behaviorStore
	behavior      *detection.BehaviorDetector
	policyStore   policyStore
}

// NewProcessor constructs the moderation processor with automatic banning.
func NewProcessor(
	store terminalRecorder,
	profiles telegramClient,
	detector profileDetector,
	options ...ProcessorOption,
) (*Processor, error) {
	if store == nil {
		return nil, fmt.Errorf("terminal event recorder is required")
	}
	if profiles == nil {
		return nil, fmt.Errorf("profile fetcher is required")
	}
	if detector == nil {
		return nil, fmt.Errorf("profile detector is required")
	}
	processor := &Processor{
		store:     store,
		profiles:  profiles,
		detector:  detector,
		messages:  detection.NewMessageAdDetector(),
		decisions: NewDecisionEngine(),
	}
	for _, option := range options {
		if option == nil {
			return nil, fmt.Errorf("processor option must not be nil")
		}
		if err := option(processor); err != nil {
			return nil, err
		}
	}
	return processor, nil
}

// Process detects spam and atomically records a decision plus any requested
// action. Profile fetch failures never raise risk by themselves.
func (p *Processor) Process(ctx context.Context, event events.TelegramUpdate) error {
	message := messageContent(event.Payload)
	messageSignal := p.messages.Analyze(message)
	var ocrFailureSignal *detection.Signal
	if p.imageText != nil && signalScore(messageSignal) < 0.90 {
		if fileID := imageFileID(event.Payload); fileID != "" {
			ocrText, err := p.imageText.ExtractText(ctx, fileID)
			if err != nil {
				if isRetryableProfileError(err) {
					return fmt.Errorf("extract Telegram image text: %w", err)
				}
				signal := ocrErrorSignal()
				ocrFailureSignal = &signal
			} else {
				message.OCRText = strings.TrimSpace(ocrText)
				messageSignal = p.messages.Analyze(message)
			}
		}
	}
	profileSignal := p.detector.Analyze(detection.Profile{})
	profileContext := detection.Profile{}
	var profileFetchErr error
	target := moderationTargetFrom(event.Payload)
	userID := target.UserID
	if userID == 0 {
		profileSignal.ReasonCodes = []string{detection.ReasonNoSender}
	} else {
		profile, err := p.profiles.FetchProfile(ctx, userID)
		if err != nil {
			profileFetchErr = err
			profileSignal.Status = detection.StatusError
			profileSignal.ReasonCodes = []string{detection.ReasonProfileFetchFailed}
		} else {
			profileContext = profile
			profileSignal = p.detector.Analyze(profile)
		}
	}
	signals := []detection.Signal{messageSignal, profileSignal}
	if ocrFailureSignal != nil {
		signals = append(signals, *ocrFailureSignal)
	}
	actionTarget := target.actionTarget()
	if p.behaviorStore != nil && actionTarget.Kind == TargetMessage &&
		(message.Text != "" || message.Caption != "") {
		stats, err := p.behaviorStore.ObserveMessage(ctx, event, actionTarget, message)
		if err != nil {
			signals = append(signals, behaviorErrorSignal())
		} else {
			signals = append(signals, p.behavior.Analyze(stats))
		}
	}
	if p.semantic != nil {
		signals = append(signals, p.semantic.AnalyzeAdvertising(ctx, detection.SemanticAdContent{
			Message: message,
			Profile: profileContext,
		}))
	}
	preliminary := p.decisions.Decide(DecisionInput{Target: actionTarget, Signals: signals})
	if profileFetchErr != nil && preliminary.RiskScore < 0.90 && isRetryableProfileError(profileFetchErr) {
		return fmt.Errorf("fetch Telegram profile for moderation: %w", profileFetchErr)
	}
	isProtected := false
	automaticActionsDisabled := false
	autobanDisabled := false
	if isAutomaticAction(preliminary.AuthorizedAction) {
		if p.policyStore != nil {
			policy, err := p.policyStore.GetCommunityPolicy(ctx, event.TenantID, target.ChatID, target.UserID)
			if err != nil {
				return fmt.Errorf("load community moderation policy: %w", err)
			}
			isProtected = policy.IsAllowlisted
			automaticActionsDisabled = !policy.AutomaticActionsEnabled || policy.ProtectionLevel == "OBSERVE"
			autobanDisabled = !policy.AutobanEnabled
		}
		if !isProtected && target.UserID > 0 {
			status, err := p.profiles.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
			if err != nil {
				return fmt.Errorf("get Telegram member status before automatic action: %w", err)
			}
			isProtected = status == "creator" || status == "administrator"
		}
	}
	decision := p.decisions.Decide(DecisionInput{
		Target:                   actionTarget,
		Signals:                  signals,
		IsProtected:              isProtected,
		AutomaticActionsDisabled: automaticActionsDisabled,
		AutobanDisabled:          autobanDisabled,
	})
	if ocrFailureSignal != nil && decision.RiskScore < 0.90 {
		decision.RecommendedAction = ActionReview
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonInsufficientEvidence
	}
	state := terminalStateFor(decision.AuthorizedAction)
	actions := []ActionRequest{}
	if isAutomaticAction(decision.AuthorizedAction) {
		actions = actionRequestsFor(event.EventID, decision.AuthorizedAction, actionTarget)
	}

	if err := p.store.RecordTerminal(ctx, event, Outcome{
		State:    state,
		Input:    inputFeatures(event.Payload, message),
		Signals:  signals,
		Decision: decision,
		Actions:  actions,
	}); err != nil {
		return fmt.Errorf("record terminal moderation state: %w", err)
	}
	return nil
}

func ocrErrorSignal() detection.Signal {
	return detection.Signal{
		SchemaVersion:   "1",
		Detector:        "image.ocr",
		DetectorVersion: "tesseract-v1",
		Category:        "content.extraction",
		Status:          detection.StatusError,
		Severity:        detection.SeverityInfo,
		ReasonCodes:     []string{detection.ReasonOCRFailed},
		MatchedRules:    []string{},
		CreatedAt:       time.Now().UTC(),
	}
}

func signalScore(signal detection.Signal) float64 {
	if signal.Score == nil {
		return 0
	}
	return *signal.Score
}

func imageFileID(payload json.RawMessage) string {
	type photoSize struct {
		FileID   string `json:"file_id"`
		FileSize int64  `json:"file_size"`
	}
	type document struct {
		FileID   string `json:"file_id"`
		MimeType string `json:"mime_type"`
	}
	type mediaMessage struct {
		Photo    []photoSize `json:"photo"`
		Document *document   `json:"document"`
	}
	var update struct {
		Message               *mediaMessage `json:"message"`
		EditedMessage         *mediaMessage `json:"edited_message"`
		BusinessMessage       *mediaMessage `json:"business_message"`
		EditedBusinessMessage *mediaMessage `json:"edited_business_message"`
		ChannelPost           *mediaMessage `json:"channel_post"`
		EditedChannelPost     *mediaMessage `json:"edited_channel_post"`
	}
	if json.Unmarshal(payload, &update) != nil {
		return ""
	}
	for _, message := range []*mediaMessage{
		update.Message, update.EditedMessage, update.BusinessMessage,
		update.EditedBusinessMessage, update.ChannelPost, update.EditedChannelPost,
	} {
		if message == nil {
			continue
		}
		var selected photoSize
		for index, photo := range message.Photo {
			if photo.FileID != "" && (selected.FileID == "" || photo.FileSize >= selected.FileSize || index == len(message.Photo)-1) {
				selected = photo
			}
		}
		if selected.FileID != "" {
			return selected.FileID
		}
		if message.Document != nil && message.Document.FileID != "" && strings.HasPrefix(strings.ToLower(message.Document.MimeType), "image/") {
			return message.Document.FileID
		}
		return ""
	}
	return ""
}

func inputFeatures(payload json.RawMessage, content detection.MessageContent) InputFeatures {
	type mediaMessage struct {
		Photo     []json.RawMessage `json:"photo"`
		Video     json.RawMessage   `json:"video"`
		Animation json.RawMessage   `json:"animation"`
		Document  json.RawMessage   `json:"document"`
		Sticker   json.RawMessage   `json:"sticker"`
		VideoNote json.RawMessage   `json:"video_note"`
		Voice     json.RawMessage   `json:"voice"`
		Audio     json.RawMessage   `json:"audio"`
	}
	var update struct {
		Message               *mediaMessage   `json:"message"`
		EditedMessage         *mediaMessage   `json:"edited_message"`
		BusinessMessage       *mediaMessage   `json:"business_message"`
		EditedBusinessMessage *mediaMessage   `json:"edited_business_message"`
		ChannelPost           *mediaMessage   `json:"channel_post"`
		EditedChannelPost     *mediaMessage   `json:"edited_channel_post"`
		CallbackQuery         json.RawMessage `json:"callback_query"`
		MessageReaction       json.RawMessage `json:"message_reaction"`
	}
	features := InputFeatures{
		HasLink:            content.HasLink,
		TextLength:         len([]rune(strings.TrimSpace(strings.Join([]string{content.Text, content.Caption}, " ")))),
		OCRTextLength:      len([]rune(content.OCRText)),
		ContentFingerprint: detection.MessageFingerprint(content),
		MediaTypes:         []string{},
	}
	if json.Unmarshal(payload, &update) != nil {
		features.UpdateKind = "unknown"
		return features
	}
	candidates := []struct {
		kind    string
		message *mediaMessage
	}{
		{"message", update.Message},
		{"edited_message", update.EditedMessage},
		{"business_message", update.BusinessMessage},
		{"edited_business_message", update.EditedBusinessMessage},
		{"channel_post", update.ChannelPost},
		{"edited_channel_post", update.EditedChannelPost},
	}
	for _, candidate := range candidates {
		if candidate.message == nil {
			continue
		}
		features.UpdateKind = candidate.kind
		message := candidate.message
		if len(message.Photo) > 0 {
			features.MediaTypes = append(features.MediaTypes, "photo")
		}
		for _, media := range []struct {
			kind string
			raw  json.RawMessage
		}{
			{"video", message.Video}, {"animation", message.Animation},
			{"document", message.Document}, {"sticker", message.Sticker},
			{"video_note", message.VideoNote}, {"voice", message.Voice},
			{"audio", message.Audio},
		} {
			if len(media.raw) > 0 && string(media.raw) != "null" {
				features.MediaTypes = append(features.MediaTypes, media.kind)
			}
		}
		return features
	}
	if len(update.CallbackQuery) > 0 && string(update.CallbackQuery) != "null" {
		features.UpdateKind = "callback_query"
	} else if len(update.MessageReaction) > 0 && string(update.MessageReaction) != "null" {
		features.UpdateKind = "message_reaction"
	} else {
		features.UpdateKind = "unknown"
	}
	return features
}

func isRetryableProfileError(err error) bool {
	var apiErr *telegramapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode == 0 || apiErr.ErrorCode == 429 || apiErr.ErrorCode >= 500
	}
	var networkErr net.Error
	return errors.As(err, &networkErr) && (networkErr.Timeout() || networkErr.Temporary())
}

func actionRequestsFor(eventID string, action ActionType, target ActionTarget) []ActionRequest {
	requests := []ActionRequest{}
	appendAction := func(actionType ActionType) {
		requests = append(requests, ActionRequest{
			Type: actionType, Target: target,
			IdempotencyKey: actionIdempotencyKey(eventID, actionType, target),
		})
	}
	if action == ActionBanUser {
		switch target.Kind {
		case TargetMessage:
			appendAction(ActionDeleteMessage)
		case TargetReaction:
			appendAction(ActionDeleteReaction)
		}
	}
	appendAction(action)
	return requests
}

func terminalStateFor(action ActionType) TerminalState {
	switch action {
	case ActionAllow:
		return ProcessedAllow
	case ActionReview:
		return ProcessedReview
	default:
		return DecidedPendingAction
	}
}

func isAutomaticAction(action ActionType) bool {
	return action == ActionDeleteMessage || action == ActionDeleteReaction || action == ActionBanUser
}

func behaviorErrorSignal() detection.Signal {
	return detection.Signal{
		SchemaVersion:   "1",
		Detector:        "behavior.spam",
		DetectorVersion: "behavior-v1",
		Category:        "spam.behavior",
		Status:          detection.StatusError,
		Severity:        detection.SeverityInfo,
		ReasonCodes:     []string{detection.ReasonBehaviorStoreFailed},
		MatchedRules:    []string{},
	}
}

func messageContent(payload json.RawMessage) detection.MessageContent {
	type entity struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	}
	type message struct {
		Text            string   `json:"text"`
		Caption         string   `json:"caption"`
		Entities        []entity `json:"entities"`
		CaptionEntities []entity `json:"caption_entities"`
	}
	var update struct {
		Message               *message `json:"message"`
		EditedMessage         *message `json:"edited_message"`
		BusinessMessage       *message `json:"business_message"`
		EditedBusinessMessage *message `json:"edited_business_message"`
		ChannelPost           *message `json:"channel_post"`
		EditedChannelPost     *message `json:"edited_channel_post"`
	}
	if json.Unmarshal(payload, &update) != nil {
		return detection.MessageContent{}
	}

	candidates := []*message{
		update.Message,
		update.EditedMessage,
		update.BusinessMessage,
		update.EditedBusinessMessage,
		update.ChannelPost,
		update.EditedChannelPost,
	}
	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		content := detection.MessageContent{
			Text:    candidate.Text,
			Caption: candidate.Caption,
		}
		for _, entity := range append(candidate.Entities, candidate.CaptionEntities...) {
			if entity.Type == "url" || entity.Type == "text_link" {
				content.HasLink = true
				if entity.URL != "" {
					content.URLs = appendUniqueURL(content.URLs, entity.URL)
				}
			}
		}
		for _, extracted := range extractURLs(candidate.Text + " " + candidate.Caption) {
			content.URLs = appendUniqueURL(content.URLs, extracted)
		}
		content.HasLink = content.HasLink || len(content.URLs) > 0
		return content
	}
	return detection.MessageContent{}
}

var messageURLPattern = regexp.MustCompile(`(?i)(?:https?://[^\s<>"']+|(?:t|telegram)\.me/[a-z0-9_/?=&.%-]+|(?:t|telegram)\s*\[\s*\.\s*\]\s*me/[a-z0-9_/?=&.%-]+|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:ru|com|net|org|io|me|ai|app|site|online|xyz)(?:/[^\s<>"']*)?)`)

func extractURLs(value string) []string {
	matches := messageURLPattern.FindAllString(value, -1)
	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		match = strings.TrimRight(match, ".,;:!?)]}")
		urls = appendUniqueURL(urls, match)
	}
	return urls
}

func appendUniqueURL(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

type moderationTarget struct {
	ChatID    int64
	UserID    int64
	MessageID int64
	ChatType  string
	Kind      TargetKind
}

func (t moderationTarget) actionTarget() ActionTarget {
	if t.ChatID == 0 || t.MessageID <= 0 {
		return ActionTarget{}
	}
	if t.Kind == TargetReaction && t.UserID <= 0 {
		return ActionTarget{}
	}
	if t.ChatType != "group" && t.ChatType != "supergroup" && t.ChatType != "channel" {
		return ActionTarget{}
	}
	return ActionTarget{Kind: t.Kind, ChatID: t.ChatID, UserID: t.UserID, MessageID: t.MessageID}
}

func moderationTargetFrom(payload json.RawMessage) moderationTarget {
	type sender struct {
		ID int64 `json:"id"`
	}
	type chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	}
	type message struct {
		MessageID int64   `json:"message_id"`
		From      *sender `json:"from"`
		Chat      *chat   `json:"chat"`
	}
	var update struct {
		Message               *message `json:"message"`
		EditedMessage         *message `json:"edited_message"`
		BusinessMessage       *message `json:"business_message"`
		EditedBusinessMessage *message `json:"edited_business_message"`
		ChannelPost           *message `json:"channel_post"`
		EditedChannelPost     *message `json:"edited_channel_post"`
		CallbackQuery         *struct {
			From    *sender  `json:"from"`
			Message *message `json:"message"`
		} `json:"callback_query"`
		MessageReaction *struct {
			User        *sender           `json:"user"`
			Chat        *chat             `json:"chat"`
			MessageID   int64             `json:"message_id"`
			NewReaction []json.RawMessage `json:"new_reaction"`
		} `json:"message_reaction"`
	}
	if json.Unmarshal(payload, &update) != nil {
		return moderationTarget{}
	}
	targetFrom := func(chatValue *chat, senderValue *sender, messageID int64, kind TargetKind) moderationTarget {
		target := moderationTarget{MessageID: messageID, Kind: kind}
		if senderValue != nil {
			target.UserID = senderValue.ID
		}
		if chatValue != nil {
			target.ChatID = chatValue.ID
			target.ChatType = chatValue.Type
		}
		return target
	}
	for _, candidate := range []*message{
		update.Message,
		update.EditedMessage,
		update.BusinessMessage,
		update.EditedBusinessMessage,
		update.ChannelPost,
		update.EditedChannelPost,
	} {
		if candidate != nil {
			return targetFrom(candidate.Chat, candidate.From, candidate.MessageID, TargetMessage)
		}
	}
	if update.CallbackQuery != nil && update.CallbackQuery.From != nil && update.CallbackQuery.From.ID > 0 {
		var callbackChat *chat
		if update.CallbackQuery.Message != nil {
			callbackChat = update.CallbackQuery.Message.Chat
		}
		messageID := int64(0)
		if update.CallbackQuery.Message != nil {
			messageID = update.CallbackQuery.Message.MessageID
		}
		return targetFrom(callbackChat, update.CallbackQuery.From, messageID, TargetMessage)
	}
	if update.MessageReaction != nil && len(update.MessageReaction.NewReaction) > 0 && update.MessageReaction.User != nil && update.MessageReaction.User.ID > 0 {
		return targetFrom(update.MessageReaction.Chat, update.MessageReaction.User, update.MessageReaction.MessageID, TargetReaction)
	}
	return moderationTarget{}
}
