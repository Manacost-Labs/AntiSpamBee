package moderation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/telegramapi"
)

var ErrContentUnavailable = errors.New("multimodal moderation temporarily unavailable")

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
	State       TerminalState
	Input       InputFeatures
	Signals     []detection.Signal
	Decision    Decision
	Actions     []ActionRequest
	Evidence    *Evidence
	Command     *CommandCommit
	QueueReview bool
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
	Notification   DeletionNotification
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
type contentAdAnalyzer interface {
	AnalyzeContent(context.Context, detection.SemanticAdContent) []detection.Signal
}
type imageDownloader interface {
	DownloadFile(context.Context, string, int64) ([]byte, error)
}

type imageTextExtractor interface {
	ExtractText(context.Context, string) (string, error)
}

type behaviorStore interface {
	ObserveMessage(context.Context, events.TelegramUpdate, ActionTarget, detection.MessageContent) (detection.BehaviorStats, error)
}

type policyStore interface {
	GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error)
	IsAuthorizedSenderChat(context.Context, string, int64, int64) (bool, error)
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

func WithContentAnalyzer(analyzer contentAdAnalyzer, downloader imageDownloader, chatID int64) ProcessorOption {
	return func(processor *Processor) error {
		if analyzer == nil || downloader == nil {
			return fmt.Errorf("content analyzer and image downloader are required")
		}
		processor.content = analyzer
		processor.images = downloader
		processor.contentChatID = chatID
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
	store              terminalRecorder
	profiles           telegramClient
	detector           profileDetector
	messages           *detection.MessageAdDetector
	channels           *detection.AdvertisingChannelDetector
	imageText          imageTextExtractor
	semantic           semanticAdAnalyzer
	content            contentAdAnalyzer
	images             imageDownloader
	contentChatID      int64
	advertisingBanChat int64
	banVerifier        contentAdAnalyzer
	operationsChatID   int64
	campaignKey        []byte
	campaigns          campaignStore
	decisions          *DecisionEngine
	behaviorStore      behaviorStore
	behavior           *detection.BehaviorDetector
	policyStore        policyStore
}

// NewProcessor constructs the moderation processor with automatic moderation.
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
		channels:  detection.NewAdvertisingChannelDetector(),
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
	target := moderationTargetFrom(event.Payload)
	useContent := p.content != nil && (p.contentChatID == 0 || p.contentChatID == target.ChatID)
	attachment := imageAttachment(event.Payload)
	fileID := attachment.BestImageFileID(0)
	var ocrFailureSignal *detection.Signal
	if p.imageText != nil && signalScore(messageSignal) < 0.90 {
		if fileID != "" {
			ocrText, err := p.imageText.ExtractText(ctx, fileID)
			if err != nil {
				if !useContent && isRetryableProfileError(err) {
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
	channelSignal := p.channels.Analyze(profileContext)
	signals := []detection.Signal{messageSignal, profileSignal, channelSignal, p.channels.AnalyzeProhibited(profileContext)}
	if ocrFailureSignal != nil {
		signals = append(signals, *ocrFailureSignal)
	}
	actionTarget := target.actionTarget()
	if p.behaviorStore != nil && actionTarget.Kind == TargetMessage && actionTarget.UserID > 0 &&
		(message.Text != "" || message.Caption != "") {
		stats, err := p.behaviorStore.ObserveMessage(ctx, event, actionTarget, message)
		if err != nil {
			signals = append(signals, behaviorErrorSignal())
		} else {
			signals = append(signals, p.behavior.Analyze(stats))
		}
	}
	knownMessageAuthor := actionTarget.Kind == TargetMessage && actionTarget.UserID > 0
	confirmedOffer := knownMessageAuthor &&
		signalScore(messageSignal) >= .90 && messageSignal.EvidenceCoverage >= .50 &&
		(slices.Contains(messageSignal.ReasonCodes, detection.ReasonRecruitmentSpam) ||
			slices.Contains(messageSignal.ReasonCodes, detection.ReasonEducationDocumentOffer))
	confirmedEducationChannel := knownMessageAuthor && signalScore(channelSignal) >= .90 && channelSignal.EvidenceCoverage >= .50 &&
		slices.Contains(channelSignal.ReasonCodes, detection.ReasonEducationDocumentOffer)
	hasMessageContent := strings.TrimSpace(message.Text+message.Caption+message.OCRText) != ""
	useSemantic := (p.semantic != nil || useContent) && !confirmedOffer
	var checkedContent *detection.SemanticAdContent
	textFallbackClear := false
	addSemanticSignal := func() {
		input := detection.SemanticAdContent{Message: message, Profile: profileContext}
		if !useContent {
			signals = append(signals, p.semantic.AnalyzeAdvertising(ctx, input))
			return
		}
		if imageID := attachment.BestImageFileID(detection.MaxSemanticImageBytes); imageID != "" {
			image, err := p.images.DownloadFile(ctx, imageID, detection.MaxSemanticImageBytes)
			if err != nil {
				signal := ocrErrorSignal()
				signal.Detector = "image.download"
				signal.DetectorVersion = "telegram-file-v1"
				signal.ReasonCodes = []string{detection.ReasonSemanticImageUnavailable}
				ocrFailureSignal = &signal
				signals = append(signals, signal)
			} else {
				input.Image = image
				hasMessageContent = hasMessageContent || len(image) > 0
			}
		}
		input.ProfileImages = p.profileImages(ctx, profileContext.PersonalChannel)
		checkedContent = &input
		results := p.content.AnalyzeContent(ctx, input)
		signals = append(signals, results...)
		if p.semantic != nil && slices.ContainsFunc(results, func(signal detection.Signal) bool {
			return signal.Status == detection.StatusError
		}) {
			fallback := p.semantic.AnalyzeAdvertising(ctx, input)
			textFallbackClear = fallback.Status == detection.StatusAvailable && fallback.Score != nil && *fallback.Score >= 0 && *fallback.Score <= .10 &&
				fileID == "" && profileContext.PersonalChannel == nil && strings.TrimSpace(profileContext.Bio) == ""
			signals = append(signals, fallback)
		}
	}
	if useSemantic && !confirmedEducationChannel {
		addSemanticSignal()
	}
	preliminary := p.decisions.Decide(DecisionInput{Target: actionTarget, Signals: signals, HasMessageContent: hasMessageContent})
	if profileFetchErr != nil && preliminary.RiskScore < 0.90 && isRetryableProfileError(profileFetchErr) {
		return fmt.Errorf("fetch Telegram profile for moderation: %w", profileFetchErr)
	}
	isProtected := target.isAdminOrigin()
	automaticActionsDisabled := false
	autobanDisabled := false
	moderatorChatID := int64(0)
	policy := CommunityPolicy{ChatID: target.ChatID, ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true}
	operations := p.operationsChatID != 0 && target.ChatID == p.operationsChatID && knownMessageAuthor
	var indicators []CampaignIndicator
	if operations && !detection.IsPromotionWarning(message.Text+" "+message.Caption+" "+message.OCRText) {
		indicators = campaignIndicators(p.campaignKey, message, attachment.StableImageID())
	}
	needsReviewPolicy := operations && (len(indicators) > 0 || ocrFailureSignal != nil || slices.ContainsFunc(signals, func(signal detection.Signal) bool {
		return signal.Detector == detection.SemanticMessageDetector && signal.Status == detection.StatusError
	}))
	if preliminary.AuthorizedAction != ActionAllow || needsReviewPolicy {
		if p.policyStore != nil {
			var err error
			policy, err = p.policyStore.GetCommunityPolicy(ctx, event.TenantID, target.ChatID, target.UserID)
			if err != nil {
				return fmt.Errorf("load community moderation policy: %w", err)
			}
			isProtected = isProtected || policy.IsAllowlisted
			if !isProtected && target.SenderChatID != 0 {
				isProtected, err = p.policyStore.IsAuthorizedSenderChat(ctx, event.TenantID, target.ChatID, target.SenderChatID)
				if err != nil {
					return fmt.Errorf("check authorized Telegram sender chat: %w", err)
				}
			}
			automaticActionsDisabled = !policy.AutomaticActionsEnabled ||
				(policy.ProtectionLevel != "STANDARD" && policy.ProtectionLevel != "STRICT")
			autobanDisabled = !policy.AutobanEnabled
			moderatorChatID = policy.ModeratorChatID
		}
	}
	// Channel evidence can authorize deletion only under STRICT policy.
	if useSemantic && confirmedEducationChannel && (policy.ProtectionLevel != "STRICT" || automaticActionsDisabled) {
		addSemanticSignal()
	}
	decisionInput := DecisionInput{
		Target:                          actionTarget,
		HasMessageContent:               hasMessageContent,
		Signals:                         signals,
		IsProtected:                     isProtected,
		UnverifiedSender:                target.UserID <= 0 && !isProtected,
		AutomaticActionsDisabled:        automaticActionsDisabled,
		AutobanDisabled:                 autobanDisabled,
		AllowAdvertisingChannelDeletion: policy.ProtectionLevel == "STRICT",
	}
	candidate := p.decisions.Decide(decisionInput)
	if isAutomaticAction(candidate.AuthorizedAction) && !isProtected && target.UserID > 0 {
		status, err := p.profiles.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
		if err != nil {
			return fmt.Errorf("get Telegram member status before automatic action: %w", err)
		}
		decisionInput.IsProtected = status == "creator" || status == "administrator"
	}
	decision := p.decisions.Decide(decisionInput)
	if useContent && !textFallbackClear && actionTarget.Kind == TargetMessage && decision.AuthorizedAction == ActionAllow {
		for _, signal := range signals {
			if signal.Detector != detection.SemanticMessageDetector || signal.Status != detection.StatusError {
				continue
			}
			if target.MessageDate > 0 && time.Since(time.Unix(target.MessageDate, 0)) < 45*time.Second &&
				slices.Contains(signal.ReasonCodes, detection.ReasonOpenRouterTemporarilyUnavailable) {
				return ErrContentUnavailable
			}
			decision.RecommendedAction = ActionReview
			decision.AuthorizedAction = ActionReview
			decision.AuthorizationReason = detection.ReasonOpenRouterFailed
			break
		}
	}
	decision, confirmation := p.verifyAdvertisingAction(ctx, decision, decisionInput, checkedContent)
	signals = append(signals, confirmation...)
	isProtected = decisionInput.IsProtected
	if ocrFailureSignal != nil && decision.RiskScore < 0.90 && decision.AuthorizedAction == ActionAllow {
		decision.RecommendedAction = ActionReview
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonMediaAnalysisUnavailable
	}
	if len(indicators) > 0 && !isProtected {
		kinds, err := p.campaigns.ObserveCampaign(ctx, event.TenantID, actionTarget, indicators, isAutomaticAction(decision.AuthorizedAction))
		if err != nil {
			return fmt.Errorf("observe advertising campaign: %w", err)
		}
		if len(kinds) > 0 && !isAutomaticAction(decision.AuthorizedAction) {
			decision.RecommendedAction = ActionReview
			decision.AuthorizedAction = ActionReview
			decision.AuthorizationReason = ReasonRepeatedCampaign
			score, confidence := .60, .70
			signals = append(signals, detection.Signal{SchemaVersion: "1", Detector: "behavior.campaign", DetectorVersion: "v1",
				Category: "spam.behavior", Status: detection.StatusAvailable, Severity: detection.SeverityMedium,
				Score: &score, Confidence: &confidence, EvidenceCoverage: 1, ReasonCodes: []string{ReasonRepeatedCampaign},
				MatchedRules: kinds, CreatedAt: time.Now().UTC()})
		}
	}
	state := terminalStateFor(decision.AuthorizedAction)
	actions := []ActionRequest{}
	if isAutomaticAction(decision.AuthorizedAction) {
		actions = actionRequestsFor(
			event.EventID,
			decision.AuthorizedAction,
			actionTarget,
			deletionNotification(event.Payload, message, signals, decision, actionTarget.UserID, moderatorChatID),
		)
	}

	var evidence *Evidence
	sampled := actionTarget.Kind == TargetMessage && evaluationSample(event.TenantID, event.EventID)
	if decision.AuthorizedAction != ActionAllow || sampled {
		evidence = newEvidence(actionTarget, message, profileContext, signals, decision, policy, isProtected)
		evidence.AuthorUsername = messageAuthorUsername(event.Payload)
		evidence.EvaluationSample = sampled
	}
	if err := p.store.RecordTerminal(ctx, event, Outcome{
		State:       state,
		Input:       inputFeatures(event.Payload, message),
		Signals:     signals,
		Decision:    decision,
		Actions:     actions,
		Evidence:    evidence,
		QueueReview: operations && decision.NeedsModeratorReview(),
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

func (p *Processor) profileImages(ctx context.Context, channel *detection.PersonalChannel) []detection.ProfileImage {
	if channel == nil || channel.Username == "" {
		return nil
	}
	var images []detection.ProfileImage
	attempts := 0
	for index, fileID := range channel.RecentPostImageIDs {
		if fileID == "" {
			continue
		}
		if attempts == detection.MaxProfileImages {
			break
		}
		attempts++
		if image, err := p.images.DownloadFile(ctx, fileID, detection.MaxProfileImageBytes); err == nil && len(image) > 0 {
			images = append(images, detection.ProfileImage{PostNumber: index + 1, Data: image})
		}
	}
	return images
}

func imageAttachment(payload json.RawMessage) *telegramapi.ImageAttachment {
	var update struct {
		Message               *telegramapi.ImageAttachment `json:"message"`
		EditedMessage         *telegramapi.ImageAttachment `json:"edited_message"`
		BusinessMessage       *telegramapi.ImageAttachment `json:"business_message"`
		EditedBusinessMessage *telegramapi.ImageAttachment `json:"edited_business_message"`
		ChannelPost           *telegramapi.ImageAttachment `json:"channel_post"`
		EditedChannelPost     *telegramapi.ImageAttachment `json:"edited_channel_post"`
	}
	if json.Unmarshal(payload, &update) != nil {
		return nil
	}
	for _, message := range []*telegramapi.ImageAttachment{
		update.Message, update.EditedMessage, update.BusinessMessage,
		update.EditedBusinessMessage, update.ChannelPost, update.EditedChannelPost,
	} {
		if message != nil {
			return message
		}
	}
	return nil
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

func actionRequestsFor(eventID string, action ActionType, target ActionTarget, notifications ...DeletionNotification) []ActionRequest {
	requests := []ActionRequest{}
	var notification DeletionNotification
	if len(notifications) > 0 {
		notification = notifications[0]
	}
	appendAction := func(actionType ActionType) {
		requestNotification := DeletionNotification{}
		if actionType == ActionDeleteMessage {
			requestNotification = notification
		}
		requests = append(requests, ActionRequest{
			Type: actionType, Target: target, Notification: requestNotification,
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

func deletionNotification(
	payload json.RawMessage,
	content detection.MessageContent,
	signals []detection.Signal,
	decision Decision,
	authorUserID, moderatorChatID int64,
) DeletionNotification {
	if moderatorChatID == 0 {
		return DeletionNotification{}
	}
	message := strings.TrimSpace(strings.Join([]string{content.Text, content.Caption}, "\n"))
	if message == "" && strings.TrimSpace(content.OCRText) != "" {
		message = "[Текст с изображения]\n" + strings.TrimSpace(content.OCRText)
	}
	if message == "" {
		message = "[Медиа без текстовой подписи]"
	}
	return DeletionNotification{
		ChatID:         moderatorChatID,
		AuthorUsername: messageAuthorUsername(payload),
		AuthorUserID:   authorUserID,
		Message:        message,
		Reasons:        deletionReasons(signals),
		RiskScore:      decision.RiskScore,
	}
}

func deletionReasons(signals []detection.Signal) []string {
	reasons := []string{}
	for _, signal := range signals {
		if signal.Status != detection.StatusAvailable || signal.Score == nil || *signal.Score < 0.90 {
			continue
		}
		for _, reason := range signal.ReasonCodes {
			reasons = appendUniqueReason(reasons, reason)
		}
	}
	return reasons
}

func appendUniqueReason(reasons []string, reason string) []string {
	for _, existing := range reasons {
		if existing == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func messageAuthorUsername(payload json.RawMessage) string {
	type sender struct {
		Username string `json:"username"`
	}
	type message struct {
		From *sender `json:"from"`
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
		return ""
	}
	for _, candidate := range []*message{
		update.Message, update.EditedMessage, update.BusinessMessage,
		update.EditedBusinessMessage, update.ChannelPost, update.EditedChannelPost,
	} {
		if candidate != nil && candidate.From != nil {
			return candidate.From.Username
		}
	}
	return ""
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
	ChatID             int64
	UserID             int64
	MessageID          int64
	MessageDate        int64
	ChatType           string
	SenderChatID       int64
	IsAutomaticForward bool
	Kind               TargetKind
}

func (t moderationTarget) isAdminOrigin() bool {
	return t.SenderChatID != 0 && (t.SenderChatID == t.ChatID || t.IsAutomaticForward)
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
		MessageID          int64   `json:"message_id"`
		Date               int64   `json:"date"`
		EditDate           int64   `json:"edit_date"`
		From               *sender `json:"from"`
		Chat               *chat   `json:"chat"`
		SenderChat         *chat   `json:"sender_chat"`
		IsAutomaticForward bool    `json:"is_automatic_forward"`
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
	targetFrom := func(chatValue *chat, senderValue *sender, senderChat *chat, messageID int64, kind TargetKind) moderationTarget {
		target := moderationTarget{MessageID: messageID, Kind: kind}
		if senderValue != nil {
			target.UserID = senderValue.ID
		}
		if chatValue != nil {
			target.ChatID = chatValue.ID
			target.ChatType = chatValue.Type
		}
		if senderChat != nil {
			target.SenderChatID = senderChat.ID
			if senderChat.ID != 0 {
				// Telegram's from field is a compatibility placeholder for chat senders.
				target.UserID = 0
			}
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
			target := targetFrom(candidate.Chat, candidate.From, candidate.SenderChat, candidate.MessageID, TargetMessage)
			target.IsAutomaticForward = candidate.IsAutomaticForward
			target.MessageDate = max(candidate.Date, candidate.EditDate)
			return target
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
		return targetFrom(callbackChat, update.CallbackQuery.From, nil, messageID, TargetMessage)
	}
	if update.MessageReaction != nil && len(update.MessageReaction.NewReaction) > 0 && update.MessageReaction.User != nil && update.MessageReaction.User.ID > 0 {
		return targetFrom(update.MessageReaction.Chat, update.MessageReaction.User, nil, update.MessageReaction.MessageID, TargetReaction)
	}
	return moderationTarget{}
}
