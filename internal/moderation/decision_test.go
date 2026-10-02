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

func TestDecisionEngineReviewsStrongPersonalChannelAdWithoutMessageEvidence(t *testing.T) {
	engine := NewDecisionEngine()
	input := DecisionInput{
		Target:                          ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
		Signals:                         []detection.Signal{availableSignal("profile.personal_channel", 1, .95, 1)},
		AllowAdvertisingChannelDeletion: true,
	}
	decision := engine.Decide(input)
	if decision.AuthorizedAction != ActionReview || decision.AuthorizationReason != ReasonMessageEvidenceRequired {
		t.Fatalf("decision = %+v, want profile-only REVIEW", decision)
	}

	input.IsProtected = true
	if decision := engine.Decide(input); decision.AuthorizedAction != ActionReview {
		t.Fatalf("protected decision = %+v, want REVIEW", decision)
	}

	input.IsProtected = false
	input.Target.Kind = TargetReaction
	if decision := engine.Decide(input); decision.AuthorizedAction != ActionReview {
		t.Fatalf("reaction decision = %+v, want REVIEW", decision)
	}
}

func TestDecisionEngineDeletesOnlyConfirmedAdvertisingChannelsWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name                                  string
		enabled, protected, unknown, disabled bool
		kind                                  TargetKind
		excerpt                               string
		want                                  ActionType
	}{
		{"confirmed channel", true, false, false, false, TargetMessage, "complete promotional offer", ActionDeleteMessage},
		{"policy disabled", false, false, false, false, TargetMessage, "complete promotional offer", ActionReview},
		{"administrator", true, true, false, false, TargetMessage, "complete promotional offer", ActionReview},
		{"unknown author", true, false, true, false, TargetMessage, "complete promotional offer", ActionReview},
		{"automatic actions disabled", true, false, false, true, TargetMessage, "complete promotional offer", ActionReview},
		{"missing post evidence", true, false, false, false, TargetMessage, "", ActionReview},
		{"reaction", true, false, false, false, TargetReaction, "complete promotional offer", ActionReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := availableSignal(detection.AdvertisingChannelDetectorName, .95, .95, 1)
			signal.EvidenceExcerpt = tc.excerpt
			decision := NewDecisionEngine().Decide(DecisionInput{
				Target:  ActionTarget{Kind: tc.kind, ChatID: -1001, UserID: 42, MessageID: 7},
				Signals: []detection.Signal{signal}, AllowAdvertisingChannelDeletion: tc.enabled,
				IsProtected: tc.protected, UnverifiedSender: tc.unknown, AutomaticActionsDisabled: tc.disabled,
			})
			if decision.AuthorizedAction != tc.want {
				t.Fatalf("decision = %+v, want %s", decision, tc.want)
			}
			if tc.want == ActionDeleteMessage && decision.AuthorizationReason != ReasonConfirmedAdvertisingChannel {
				t.Fatalf("authorization reason = %s", decision.AuthorizationReason)
			}
		})
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
