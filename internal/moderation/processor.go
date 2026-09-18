package moderation

import (
	"context"
	"encoding/json"
	"fmt"

	"antispambee/internal/detection"
	"antispambee/internal/events"
)

// TerminalState records the durable outcome of moderation processing.
type TerminalState string

const (
	// ProcessedAllow means no suspicious signal crossed the review threshold.
	ProcessedAllow TerminalState = "PROCESSED_ALLOW"
	// ProcessedReview means the event was detected but no automatic action ran.
	ProcessedReview TerminalState = "PROCESSED_REVIEW"
	// ProcessedAction means a high-risk sender was banned successfully.
	ProcessedAction TerminalState = "PROCESSED_ACTION"
)

// Outcome groups the terminal state and the evidence that produced it.
type Outcome struct {
	State   TerminalState
	Signals []detection.Signal
}

type terminalRecorder interface {
	RecordTerminal(context.Context, events.TelegramUpdate, Outcome) error
}

type telegramClient interface {
	FetchProfile(context.Context, int64) (detection.Profile, error)
	BanChatMember(context.Context, int64, int64) error
}

type profileDetector interface {
	Analyze(detection.Profile) detection.Signal
}

type semanticAdAnalyzer interface {
	AnalyzeAdvertising(context.Context, detection.SemanticAdContent) detection.Signal
}

// Processor enriches events, evaluates profile risk, and records an outcome.
type Processor struct {
	store    terminalRecorder
	profiles telegramClient
	detector profileDetector
	messages *detection.MessageAdDetector
	semantic semanticAdAnalyzer
}

// NewProcessor constructs the moderation processor with automatic banning.
func NewProcessor(
	store terminalRecorder,
	profiles telegramClient,
	detector profileDetector,
	semantic ...semanticAdAnalyzer,
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
	if len(semantic) > 1 {
		return nil, fmt.Errorf("at most one semantic ad analyzer is supported")
	}
	var semanticAnalyzer semanticAdAnalyzer
	if len(semantic) == 1 {
		if semantic[0] == nil {
			return nil, fmt.Errorf("semantic ad analyzer must not be nil")
		}
		semanticAnalyzer = semantic[0]
	}
	return &Processor{
		store:    store,
		profiles: profiles,
		detector: detector,
		messages: detection.NewMessageAdDetector(),
		semantic: semanticAnalyzer,
	}, nil
}

// Process detects spam, bans eligible high-risk senders, and records the
// terminal outcome. Profile fetch failures never raise risk by themselves.
func (p *Processor) Process(ctx context.Context, event events.TelegramUpdate) error {
	message := messageContent(event.Payload)
	messageSignal := p.messages.Analyze(message)
	profileSignal := p.detector.Analyze(detection.Profile{})
	profileContext := detection.Profile{}
	state := ProcessedAllow
	if signalRequiresReview(messageSignal) {
		state = ProcessedReview
	}

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
			if signalRequiresReview(profileSignal) {
				state = ProcessedReview
			}
		}
	}
	if state == ProcessedReview && target.canAutoBan() {
		if err := p.profiles.BanChatMember(ctx, target.ChatID, target.UserID); err != nil {
			return fmt.Errorf(
				"ban Telegram user %d from chat %d: %w",
				target.UserID,
				target.ChatID,
				err,
			)
		}
		state = ProcessedAction
	}
	signals := []detection.Signal{messageSignal, profileSignal}
	if p.semantic != nil {
		signals = append(signals, p.semantic.AnalyzeAdvertising(ctx, detection.SemanticAdContent{
			Message: message,
			Profile: profileContext,
		}))
	}

	if err := p.store.RecordTerminal(ctx, event, Outcome{
		State:   state,
		Signals: signals,
	}); err != nil {
		return fmt.Errorf("record terminal moderation state: %w", err)
	}
	return nil
}

func signalRequiresReview(signal detection.Signal) bool {
	return signal.Score != nil && *signal.Score >= 0.9
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
				break
			}
		}
		return content
	}
	return detection.MessageContent{}
}

type moderationTarget struct {
	ChatID   int64
	UserID   int64
	ChatType string
}

func (t moderationTarget) canAutoBan() bool {
	if t.ChatID == 0 || t.UserID <= 0 {
		return false
	}
	switch t.ChatType {
	case "group", "supergroup", "channel":
		return true
	default:
		return false
	}
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
		From *sender `json:"from"`
		Chat *chat   `json:"chat"`
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
			User *sender `json:"user"`
			Chat *chat   `json:"chat"`
		} `json:"message_reaction"`
	}
	if json.Unmarshal(payload, &update) != nil {
		return moderationTarget{}
	}
	targetFrom := func(chatValue *chat, senderValue *sender) moderationTarget {
		target := moderationTarget{UserID: senderValue.ID}
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
			return targetFrom(candidate.Chat, candidate.From)
		}
	}
	if update.CallbackQuery != nil && update.CallbackQuery.From != nil && update.CallbackQuery.From.ID > 0 {
		var callbackChat *chat
		if update.CallbackQuery.Message != nil {
			callbackChat = update.CallbackQuery.Message.Chat
		}
		return targetFrom(callbackChat, update.CallbackQuery.From)
	}
	if update.MessageReaction != nil && update.MessageReaction.User != nil && update.MessageReaction.User.ID > 0 {
		return targetFrom(update.MessageReaction.Chat, update.MessageReaction.User)
	}
	return moderationTarget{}
}
