package moderation

import (
	"fmt"
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
)

// TargetKind describes the Telegram object that can be moderated.
type TargetKind string

const (
	TargetNone     TargetKind = "NONE"
	TargetMessage  TargetKind = "MESSAGE"
	TargetReaction TargetKind = "REACTION"
)

const (
	ReasonBelowActionThreshold     = "BELOW_ACTION_THRESHOLD"
	ReasonInsufficientEvidence     = "INSUFFICIENT_CONFIDENCE_OR_COVERAGE"
	ReasonNoActionableTarget       = "NO_ACTIONABLE_TARGET"
	ReasonProtectedMember          = "PROTECTED_MEMBER"
	ReasonAutomaticActionsDisabled = "AUTOMATIC_ACTIONS_DISABLED"
	ReasonCertainAdvertising       = "CERTAIN_ADVERTISING"
	ReasonLikelyAdvertising        = "LIKELY_ADVERTISING"
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
	ActionID     string
	EventID      string
	TenantID     string
	LeaseOwner   string
	Type         ActionType
	Target       ActionTarget
	AttemptCount int
}

// DecisionInput is the complete, already-enriched input to the decision engine.
type DecisionInput struct {
	Target                   ActionTarget
	Signals                  []detection.Signal
	IsProtected              bool
	AutomaticActionsDisabled bool
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
// Model detectors stay in shadow until explicitly promoted by a later policy.
type DecisionEngine struct{}

func NewDecisionEngine() *DecisionEngine { return &DecisionEngine{} }

func (e *DecisionEngine) Decide(input DecisionInput) Decision {
	decision := Decision{
		RecommendedAction:   ActionAllow,
		AuthorizedAction:    ActionAllow,
		AuthorizationReason: ReasonBelowActionThreshold,
	}
	for _, signal := range input.Signals {
		if signal.Status != detection.StatusAvailable || signal.Score == nil ||
			signal.Confidence == nil || strings.HasPrefix(signal.Detector, "model.") {
			continue
		}
		if *signal.Score > decision.RiskScore {
			decision.RiskScore = *signal.Score
			decision.DecisionConfidence = *signal.Confidence
			decision.EvidenceCoverage = signal.EvidenceCoverage
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

	decision.RecommendedAction = recommendedAction(decision.RiskScore, input.Target.Kind)
	decision.AuthorizedAction = decision.RecommendedAction
	if decision.RiskScore >= 1 {
		decision.AuthorizationReason = ReasonCertainAdvertising
	} else {
		decision.AuthorizationReason = ReasonLikelyAdvertising
	}
	if decision.AuthorizedAction == ActionReview {
		decision.AuthorizationReason = ReasonNoActionableTarget
	}
	return decision
}

func recommendedAction(score float64, kind TargetKind) ActionType {
	if score >= 1 {
		return ActionBanUser
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

func actionIdempotencyKey(eventID string, action ActionType, target ActionTarget) string {
	switch action {
	case ActionBanUser:
		return fmt.Sprintf("ban:%d:%d:%s", target.ChatID, target.UserID, eventID)
	case ActionDeleteReaction:
		return fmt.Sprintf("delete-reaction:%d:%d:%d:%s", target.ChatID, target.MessageID, target.UserID, eventID)
	case ActionDeleteMessage:
		return fmt.Sprintf("delete-message:%d:%d:%s", target.ChatID, target.MessageID, eventID)
	default:
		return ""
	}
}
