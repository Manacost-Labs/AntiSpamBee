package moderation

import (
	"testing"

	"antispambee/internal/detection"
)

func TestDecisionEngineBansOnlyAtCertainRisk(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:  ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{availableSignal("message.rules", 1, 0.95, 1)},
	})

	if decision.RecommendedAction != ActionBanUser || decision.AuthorizedAction != ActionBanUser {
		t.Fatalf("actions = %q/%q, want BAN_USER", decision.RecommendedAction, decision.AuthorizedAction)
	}
}

func TestDecisionEngineDeletesMessageAtNinetyPercent(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:  ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{availableSignal("message.rules", 0.90, 0.92, 1)},
	})

	if decision.AuthorizedAction != ActionDeleteMessage {
		t.Fatalf("authorized action = %q, want DELETE_MESSAGE", decision.AuthorizedAction)
	}
}

func TestDecisionEngineDeletesReactionAtNinetyPercent(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:  ActionTarget{Kind: TargetReaction, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{availableSignal("profile.rules", 0.95, 0.95, 1)},
	})

	if decision.AuthorizedAction != ActionDeleteReaction {
		t.Fatalf("authorized action = %q, want DELETE_REACTION", decision.AuthorizedAction)
	}
}

func TestDecisionEngineKeepsModelSignalsInShadow(t *testing.T) {
	engine := NewDecisionEngine()

	decision := engine.Decide(DecisionInput{
		Target:  ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals: []detection.Signal{availableSignal("model.jev_advertising", 1, 1, 1)},
	})

	if decision.AuthorizedAction != ActionAllow {
		t.Fatalf("authorized action = %q, want ALLOW for shadow-only evidence", decision.AuthorizedAction)
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

func availableSignal(detector string, score, confidence, coverage float64) detection.Signal {
	return detection.Signal{
		Detector:         detector,
		Status:           detection.StatusAvailable,
		Score:            &score,
		Confidence:       &confidence,
		EvidenceCoverage: coverage,
	}
}
