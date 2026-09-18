package moderation

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"antispambee/internal/detection"
	"antispambee/internal/events"
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
	Signals  []detection.Signal
	Decision Decision
	Action   *ActionRequest
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
	profileSignal := p.detector.Analyze(detection.Profile{})
	profileContext := detection.Profile{}
	target := moderationTargetFrom(event.Payload)
	userID := target.UserID
	if userID == 0 {
		profileSignal.ReasonCodes = []string{detection.ReasonNoSender}
	} else {
		profile, err := p.profiles.FetchProfile(ctx, userID)
		if err != nil {
			profileSignal.Status = detection.StatusError
			profileSignal.ReasonCodes = []string{detection.ReasonProfileFetchFailed}
		} else {
			profileContext = profile
			profileSignal = p.detector.Analyze(profile)
		}
	}
	signals := []detection.Signal{messageSignal, profileSignal}
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
	isProtected := false
	automaticActionsDisabled := false
	autobanDisabled := false
	if isAutomaticAction(preliminary.AuthorizedAction) {
		if p.policyStore != nil {
			policy, err := p.policyStore.GetCommunityPolicy(ctx, event.TenantID, target.ChatID, target.UserID)
			if err != nil {
				isProtected = true
			} else {
				isProtected = policy.IsAllowlisted
				automaticActionsDisabled = !policy.AutomaticActionsEnabled || policy.ProtectionLevel == "OBSERVE"
				autobanDisabled = !policy.AutobanEnabled
			}
		}
		if !isProtected {
			status, err := p.profiles.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
			if err != nil {
				isProtected = true
			} else {
				isProtected = status == "creator" || status == "administrator"
			}
		}
	}
	decision := p.decisions.Decide(DecisionInput{
		Target:                   actionTarget,
		Signals:                  signals,
		IsProtected:              isProtected,
		AutomaticActionsDisabled: automaticActionsDisabled,
		AutobanDisabled:          autobanDisabled,
	})
	state := terminalStateFor(decision.AuthorizedAction)
	var action *ActionRequest
	if isAutomaticAction(decision.AuthorizedAction) {
		action = &ActionRequest{
			Type:           decision.AuthorizedAction,
			Target:         actionTarget,
			IdempotencyKey: actionIdempotencyKey(event.EventID, decision.AuthorizedAction, actionTarget),
		}
	}

	if err := p.store.RecordTerminal(ctx, event, Outcome{
		State:    state,
		Signals:  signals,
		Decision: decision,
		Action:   action,
	}); err != nil {
		return fmt.Errorf("record terminal moderation state: %w", err)
	}
	return nil
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

var messageURLPattern = regexp.MustCompile(`(?i)(?:https?://[^\s<>"']+|(?:t|telegram)\.me/[a-z0-9_/?=&.%-]+)`)

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
	if t.ChatID == 0 || t.UserID <= 0 || t.MessageID <= 0 {
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
		target := moderationTarget{UserID: senderValue.ID, MessageID: messageID, Kind: kind}
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
	} {
		if candidate != nil && candidate.From != nil && candidate.From.ID > 0 {
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
