package moderation

import (
	"testing"

	"antispambee/internal/detection"
)

func TestDecisionEngineHighRuleScoreDeletesWithoutBan(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		HasMessageContent: true,
		Target:            ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals:           []detection.Signal{availableSignal("message.rules", 1, 0.95, 1)},
	})

	if decision.RecommendedAction != ActionDeleteMessage || decision.AuthorizedAction != ActionDeleteMessage {
		t.Fatalf("actions = %q/%q, want DELETE_MESSAGE", decision.RecommendedAction, decision.AuthorizedAction)
	}
}

func TestDecisionEngineDeletesMessageAtNinetyPercent(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		HasMessageContent: true,
		Target:            ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals:           []detection.Signal{availableSignal("message.rules", 0.90, 0.92, 1)},
	})

	if decision.AuthorizedAction != ActionDeleteMessage {
		t.Fatalf("authorized action = %q, want DELETE_MESSAGE", decision.AuthorizedAction)
	}
}

func TestDecisionEngineReviewsReactionWithSuspiciousProfile(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:  ActionTarget{Kind: TargetReaction, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{availableSignal("profile.rules", 0.95, 0.95, 1)},
	})

	if decision.AuthorizedAction != ActionReview {
		t.Fatalf("authorized action = %q, want REVIEW", decision.AuthorizedAction)
	}
}

func TestDecisionEngineUsesHighConfidenceModelForDeleteOnly(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		HasMessageContent: true,
		Target:            ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals:           []detection.Signal{availableSignal("model.jev_advertising", 1, 0.98, 1)},
	})

	if decision.AuthorizedAction != ActionDeleteMessage || decision.RiskScore >= 1 {
		t.Fatalf("decision = %#v, want delete-only model enforcement", decision)
	}
}

func TestDecisionEngineDoesNotTreatCorrelatedSignalsAsCertainty(t *testing.T) {
	engine := NewDecisionEngine()
	decision := engine.Decide(DecisionInput{
		HasMessageContent: true,
		Target:            ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{
			availableSignal("message.rules", 0.95, 0.95, 1),
			availableSignal("model.jev_advertising", 0.96, 0.96, 1),
		},
	})
	if decision.AuthorizedAction != ActionDeleteMessage || decision.RiskScore != .96 {
		t.Fatalf("decision = %#v, want delete without synthetic certainty", decision)
	}
}

func TestDecisionEngineReviewsWhenTargetCannotBeModerated(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Signals: []detection.Signal{availableSignal("profile.rules", 0.95, 0.95, 1)},
	})

	if decision.AuthorizedAction != ActionReview {
		t.Fatalf("authorized action = %q, want REVIEW", decision.AuthorizedAction)
	}
}

func TestDecisionEngineReviewsCertainRiskWithoutTarget(t *testing.T) {
	engine := NewDecisionEngine()
	decision := engine.Decide(DecisionInput{
		Signals: []detection.Signal{availableSignal("profile.rules", 1, 1, 1)},
	})
	if decision.AuthorizedAction != ActionReview {
		t.Fatalf("authorized action = %q, want REVIEW", decision.AuthorizedAction)
	}
}

func TestDecisionEngineNeverActsOnProtectedMember(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:      ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		IsProtected: true,
		Signals:     []detection.Signal{availableSignal("message.rules", 1, 1, 1)},
	})

	if decision.AuthorizedAction != ActionReview {
		t.Fatalf("authorized action = %q, want REVIEW", decision.AuthorizedAction)
	}
	if decision.AuthorizationReason != ReasonProtectedMember {
		t.Fatalf("authorization reason = %q", decision.AuthorizationReason)
	}
}

func TestDecisionEngineRespectsDisabledAutomaticActions(t *testing.T) {
	engine := NewDecisionEngine()
	decision := engine.Decide(DecisionInput{
		Target:                   ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		AutomaticActionsDisabled: true,
		Signals:                  []detection.Signal{availableSignal("message.rules", 1, 1, 1)},
	})
	if decision.AuthorizedAction != ActionReview || decision.AuthorizationReason != ReasonAutomaticActionsDisabled {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestDecisionEngineDowngradesBanWhenAutobanDisabled(t *testing.T) {
	engine := NewDecisionEngine()
	decision := engine.Decide(DecisionInput{
		HasMessageContent: true,
		Target:            ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		AutobanDisabled:   true,
		Signals:           []detection.Signal{availableSignal("message.rules", 1, 1, 1)},
	})
	if decision.RecommendedAction != ActionDeleteMessage || decision.AuthorizedAction != ActionDeleteMessage {
		t.Fatalf("decision = %#v", decision)
	}
}

func availableSignal(detector string, score, confidence, coverage float64) detection.Signal {
	return detection.Signal{
		Detector:         detector,
		Status:           detection.StatusAvailable,
		Score:            &score,
		Confidence:       &confidence,
		EvidenceCoverage: coverage,
	}
}
