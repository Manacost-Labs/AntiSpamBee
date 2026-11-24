package moderation

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"antispambee/internal/detection"
)

// ActionType is a versioned moderation action selected by the decision engine.
type ActionType string

const (
	ActionAllow          ActionType = "ALLOW"
	ActionReview         ActionType = "REVIEW"
	ActionDeleteMessage  ActionType = "DELETE_MESSAGE"
	ActionDeleteReaction ActionType = "DELETE_REACTION"
	ActionBanUser        ActionType = "BAN_USER"
	ActionMuteUser       ActionType = "MUTE_USER"
	ActionUnbanUser      ActionType = "UNBAN_USER"
)

// TargetKind describes the Telegram object that can be moderated.
type TargetKind string

const (
	TargetNone     TargetKind = "NONE"
	TargetMessage  TargetKind = "MESSAGE"
	TargetReaction TargetKind = "REACTION"
)

const (
	ReasonBelowActionThreshold             = "BELOW_ACTION_THRESHOLD"
	ReasonInsufficientEvidence             = "INSUFFICIENT_CONFIDENCE_OR_COVERAGE"
	ReasonNoActionableTarget               = "NO_ACTIONABLE_TARGET"
	ReasonProtectedMember                  = "PROTECTED_MEMBER"
	ReasonUnverifiedSender                 = "SENDER_IDENTITY_UNVERIFIED"
	ReasonAutomaticActionsDisabled         = "AUTOMATIC_ACTIONS_DISABLED"
	ReasonAutobanDisabled                  = "AUTOBAN_DISABLED"
	ReasonCertainAdvertising               = "CERTAIN_ADVERTISING"
	ReasonLikelyAdvertising                = "LIKELY_ADVERTISING"
	ReasonMessageEvidenceRequired          = "CURRENT_MESSAGE_EVIDENCE_REQUIRED"
	ReasonProfileChannelAdvertising        = "PROFILE_CHANNEL_ADVERTISING"
	ReasonConfirmedAdvertisingChannel      = detection.ReasonConfirmedAdvertisingChannel
	ReasonConfirmedProfileAdvertising      = detection.ReasonConfirmedProfileAdvertising
	ReasonConfirmedAdultAdvertisingChannel = detection.ReasonConfirmedAdultAdvertisingChannel
	ReasonConfirmedAdultChannel            = detection.ReasonConfirmedAdultChannel
	ReasonConfirmedFraudChannel            = detection.ReasonConfirmedFraudChannel
	DecisionPolicyVersion                  = "message-evidence-v12"
)

// ActionTarget contains stable Telegram identifiers needed by an action worker.
type ActionTarget struct {
	Kind      TargetKind
	ChatID    int64
	UserID    int64
	MessageID int64
}

// ClaimedAction is a leased database action ready for one execution attempt.
type ClaimedAction struct {
	ActionID            string
	EventID             string
	TenantID            string
	LeaseOwner          string
	Type                ActionType
	Target              ActionTarget
	AttemptCount        int
	UntilDate           int64
	Notification        DeletionNotification
	AuthorizationReason string
}

// DeletionNotification is the short-lived context sent to the community
// administrator after an automatic message deletion succeeds.
type DeletionNotification struct {
	ChatID         int64
	AuthorUsername string
	AuthorUserID   int64
	Message        string
	Reasons        []string
	RiskScore      float64
}

// DecisionInput is the complete, already-enriched input to the decision engine.
type DecisionInput struct {
	Target                          ActionTarget
	HasMessageContent               bool
	Signals                         []detection.Signal
	IsProtected                     bool
	UnverifiedSender                bool
	AutomaticActionsDisabled        bool
	AutobanDisabled                 bool
	AllowAdvertisingChannelDeletion bool
}

// Decision separates detector recommendation from policy authorization.
type Decision struct {
	RiskScore           float64
	DecisionConfidence  float64
	EvidenceCoverage    float64
	RecommendedAction   ActionType
	AuthorizedAction    ActionType
	AuthorizationReason string
}

// DecisionEngine applies conservative, deterministic action thresholds.
// Automatic enforcement deletes advertising messages and permits banning only
// for confirmed adult advertising channels. Manual commands have a separate path.
type DecisionEngine struct{}

func NewDecisionEngine() *DecisionEngine { return &DecisionEngine{} }

func (e *DecisionEngine) Decide(input DecisionInput) Decision {
	decision := Decision{
		RecommendedAction:   ActionAllow,
		AuthorizedAction:    ActionAllow,
		AuthorizationReason: ReasonBelowActionThreshold,
	}
	hasMessageEvidence := false
	hasAdvertisingChannelEvidence := false
	var messageEvidence, channelEvidence, banEvidence *detection.Signal
	for _, signal := range input.Signals {
		if signal.Status != detection.StatusAvailable || signal.Score == nil ||
			signal.Confidence == nil {
			continue
		}
		if !unitInterval(*signal.Score) || !unitInterval(*signal.Confidence) || !unitInterval(signal.EvidenceCoverage) {
			continue
		}
		isModel := strings.HasPrefix(signal.Detector, "model.")
		candidateScore := *signal.Score
		if isModel && candidateScore > 0.97 {
			candidateScore = 0.97
		}
		if candidateScore > decision.RiskScore {
			decision.RiskScore = candidateScore
			decision.DecisionConfidence = *signal.Confidence
			decision.EvidenceCoverage = signal.EvidenceCoverage
		}
		if (strings.HasPrefix(signal.Detector, "message.") || signal.Detector == "model.jev_advertising" || signal.Detector == detection.SemanticMessageDetector) &&
			*signal.Score >= .90 && *signal.Confidence >= .90 && signal.EvidenceCoverage >= .50 {
			hasMessageEvidence = true
			messageEvidence = preferEvidence(messageEvidence, signal)
		}
		if (signal.Detector == detection.AdvertisingChannelDetectorName || signal.Detector == detection.SemanticProfileDetector) &&
			*signal.Score >= .90 && *signal.Confidence >= .90 && signal.EvidenceCoverage >= .50 &&
			strings.TrimSpace(signal.EvidenceExcerpt) != "" {
			hasAdvertisingChannelEvidence = true
			channelEvidence = preferEvidence(channelEvidence, signal)
			if signal.Detector == detection.AdvertisingChannelDetectorName && *signal.Score >= .98 && *signal.Confidence >= .98 && signal.EvidenceCoverage == 1 &&
				slices.Contains(signal.ReasonCodes, detection.ReasonConfirmedAdultAdvertisingChannel) {
				banEvidence = preferEvidence(banEvidence, signal)
			}
		}
		if signal.Detector == detection.ProhibitedChannelDetectorName &&
			*signal.Score >= .98 && *signal.Confidence >= .98 && signal.EvidenceCoverage == 1 &&
			strings.TrimSpace(signal.EvidenceExcerpt) != "" &&
			(slices.Contains(signal.ReasonCodes, detection.ReasonConfirmedAdultChannel) ||
				slices.Contains(signal.ReasonCodes, detection.ReasonConfirmedFraudChannel)) {
			banEvidence = preferEvidence(banEvidence, signal)
		}
	}
	// Confidence and coverage must come from evidence that can authorize this
	// action. An unrelated profile signal must not suppress a confirmed offer.
	if input.Target.Kind == TargetMessage {
		var evidence *detection.Signal
		switch {
		case input.AllowAdvertisingChannelDeletion && banEvidence != nil && input.Target.UserID > 0:
			evidence = banEvidence
		case input.HasMessageContent && messageEvidence != nil:
			evidence = messageEvidence
		case input.AllowAdvertisingChannelDeletion && channelEvidence != nil:
			evidence = channelEvidence
		}
		if evidence != nil {
			decision.DecisionConfidence = *evidence.Confidence
			decision.EvidenceCoverage = evidence.EvidenceCoverage
		}
	}

	if decision.RiskScore < 0.90 {
		return decision
	}
	if decision.DecisionConfidence < 0.90 || decision.EvidenceCoverage < 0.50 {
		decision.RecommendedAction = ActionReview
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonInsufficientEvidence
		return decision
	}
	if input.IsProtected {
		decision.RecommendedAction = recommendedAction(decision.RiskScore, input.Target.Kind)
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonProtectedMember
		return decision
	}
	if input.AutomaticActionsDisabled {
		decision.RecommendedAction = recommendedAction(decision.RiskScore, input.Target.Kind)
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonAutomaticActionsDisabled
		return decision
	}
	if input.UnverifiedSender {
		decision.RecommendedAction = ActionReview
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonUnverifiedSender
		return decision
	}
	if input.Target.Kind == TargetMessage && input.Target.UserID > 0 &&
		input.AllowAdvertisingChannelDeletion && banEvidence != nil {
		decision.RecommendedAction = ActionBanUser
		decision.AuthorizedAction = ActionBanUser
		decision.AuthorizationReason = ReasonConfirmedAdultAdvertisingChannel
		if banEvidence.Detector == detection.ProhibitedChannelDetectorName {
			decision.AuthorizationReason = ReasonConfirmedAdultChannel
			if slices.Contains(banEvidence.ReasonCodes, detection.ReasonConfirmedFraudChannel) {
				decision.AuthorizationReason = ReasonConfirmedFraudChannel
			}
		}
		if input.AutobanDisabled {
			decision.AuthorizedAction = ActionDeleteMessage
			decision.AuthorizationReason = ReasonAutobanDisabled
		}
		return decision
	}
	if input.Target.Kind == TargetMessage && input.AllowAdvertisingChannelDeletion &&
		hasAdvertisingChannelEvidence && (!input.HasMessageContent || !hasMessageEvidence) {
		decision.RecommendedAction = ActionDeleteMessage
		decision.AuthorizedAction = ActionDeleteMessage
		decision.AuthorizationReason = ReasonConfirmedAdvertisingChannel
		if channelEvidence.Detector == detection.SemanticProfileDetector {
			decision.AuthorizationReason = ReasonConfirmedProfileAdvertising
		}
		return decision
	}
	if input.Target.Kind != TargetMessage || !input.HasMessageContent || !hasMessageEvidence {
		decision.RecommendedAction = ActionReview
		decision.AuthorizedAction = ActionReview
		decision.AuthorizationReason = ReasonMessageEvidenceRequired
		return decision
	}
	decision.RecommendedAction = recommendedAction(decision.RiskScore, input.Target.Kind)
	decision.AuthorizedAction = decision.RecommendedAction
	decision.AuthorizationReason = ReasonLikelyAdvertising
	if decision.AuthorizedAction == ActionReview {
		decision.AuthorizationReason = ReasonNoActionableTarget
	}
	return decision
}

func preferEvidence(current *detection.Signal, candidate detection.Signal) *detection.Signal {
	if current == nil || *candidate.Confidence > *current.Confidence ||
		(*candidate.Confidence == *current.Confidence && candidate.EvidenceCoverage > current.EvidenceCoverage) ||
		(*candidate.Confidence == *current.Confidence && candidate.EvidenceCoverage == current.EvidenceCoverage && *candidate.Score > *current.Score) {
		return &candidate
	}
	return current
}

func recommendedAction(score float64, kind TargetKind) ActionType {
	if kind != TargetMessage && kind != TargetReaction {
		return ActionReview
	}
	switch kind {
	case TargetMessage:
		return ActionDeleteMessage
	case TargetReaction:
		return ActionDeleteReaction
	default:
		return ActionReview
	}
}

func unitInterval(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1 }

func actionIdempotencyKey(eventID string, action ActionType, target ActionTarget) string {
	switch action {
	case ActionBanUser:
		return fmt.Sprintf("ban:%d:%d:%s", target.ChatID, target.UserID, eventID)
	case ActionDeleteReaction:
		return fmt.Sprintf("delete-reaction:%d:%d:%d:%s", target.ChatID, target.MessageID, target.UserID, eventID)
	case ActionDeleteMessage:
		return fmt.Sprintf("delete-message:%d:%d:%s", target.ChatID, target.MessageID, eventID)
	case ActionMuteUser:
		return fmt.Sprintf("mute:%d:%d:%s", target.ChatID, target.UserID, eventID)
	case ActionUnbanUser:
		return fmt.Sprintf("unban:%d:%d:%s", target.ChatID, target.UserID, eventID)
	default:
		return ""
	}
}
