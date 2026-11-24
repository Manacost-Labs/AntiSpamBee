package moderation

import (
	"fmt"
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

func TestDecisionEngineBansOnlyStrongConfirmedAdultChannelWithPolicyPermission(t *testing.T) {
	for _, tc := range []struct {
		name                                                         string
		score, confidence, coverage                                  float64
		protected, unknown, actionsDisabled, autobanDisabled, strict bool
		detector, excerpt                                            string
		kind                                                         TargetKind
		want                                                         ActionType
	}{
		{"confirmed adult channel", 1, .99, 1, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionBanUser},
		{"administrator", 1, .99, 1, true, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionReview},
		{"unknown sender", 1, .99, 1, false, true, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionReview},
		{"automatic actions disabled", 1, .99, 1, false, false, true, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionReview},
		{"autoban disabled", 1, .99, 1, false, false, false, true, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionDeleteMessage},
		{"standard mode", 1, .99, 1, false, false, false, false, false, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionReview},
		{"lower risk", .97, .99, 1, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionDeleteMessage},
		{"lower confidence", 1, .97, 1, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionDeleteMessage},
		{"incomplete evidence", 1, .99, .75, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetMessage, ActionDeleteMessage},
		{"missing excerpt", 1, .99, 1, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "", TargetMessage, ActionReview},
		{"broad profile rules", 1, .99, 1, false, false, false, false, true, "profile.personal_channel", "adult access offer", TargetMessage, ActionReview},
		{"reaction", 1, .99, 1, false, false, false, false, true, detection.AdvertisingChannelDetectorName, "adult access offer", TargetReaction, ActionReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := availableSignal(tc.detector, tc.score, tc.confidence, tc.coverage)
			signal.EvidenceExcerpt = tc.excerpt
			signal.ReasonCodes = []string{detection.ReasonConfirmedAdultAdvertisingChannel}
			decision := NewDecisionEngine().Decide(DecisionInput{
				Target: ActionTarget{Kind: tc.kind, ChatID: -1001, UserID: 42, MessageID: 7}, Signals: []detection.Signal{signal},
				IsProtected: tc.protected, UnverifiedSender: tc.unknown, AutomaticActionsDisabled: tc.actionsDisabled,
				AutobanDisabled: tc.autobanDisabled, AllowAdvertisingChannelDeletion: tc.strict,
			})
			if decision.AuthorizedAction != tc.want {
				t.Fatalf("decision = %+v, want %s", decision, tc.want)
			}
			if tc.want == ActionBanUser && decision.AuthorizationReason != ReasonConfirmedAdultAdvertisingChannel {
				t.Fatalf("ban reason = %s", decision.AuthorizationReason)
			}
			if tc.autobanDisabled && decision.RecommendedAction != ActionBanUser {
				t.Fatalf("autoban-disabled recommendation = %s", decision.RecommendedAction)
			}
		})
	}
}

func TestDecisionEngineUsesActionEvidenceDespiteUnrelatedHigherProfileRisk(t *testing.T) {
	for _, tc := range []struct {
		name, detector       string
		confidence, coverage float64
		strict               bool
		want                 ActionType
	}{
		{"message with lower confidence profile", "message.rules", .3, 1, false, ActionDeleteMessage},
		{"message with incomplete profile", "message.rules", .99, .2, false, ActionDeleteMessage},
		{"channel tied with weaker profile", detection.AdvertisingChannelDetectorName, .3, 1, true, ActionBanUser},
		{"channel tied with incomplete profile", detection.AdvertisingChannelDetectorName, .99, .2, true, ActionBanUser},
	} {
		for _, profileFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/profile-first=%v", tc.name, profileFirst), func(t *testing.T) {
				profile := availableSignal("profile.personal_channel", 1, tc.confidence, tc.coverage)
				action := availableSignal(tc.detector, .95, .92, 1)
				if tc.strict {
					action = availableSignal(tc.detector, 1, .99, 1)
					action.EvidenceExcerpt = "Complete adult access offer"
					action.ReasonCodes = []string{detection.ReasonConfirmedAdultAdvertisingChannel}
				}
				signals := []detection.Signal{profile, action}
				if !profileFirst {
					signals[0], signals[1] = signals[1], signals[0]
				}
				decision := NewDecisionEngine().Decide(DecisionInput{Target: ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7}, HasMessageContent: true, Signals: signals, AllowAdvertisingChannelDeletion: tc.strict})
				if decision.AuthorizedAction != tc.want {
					t.Fatalf("decision = %+v, want %s", decision, tc.want)
				}
				if decision.DecisionConfidence != *action.Confidence || decision.EvidenceCoverage != action.EvidenceCoverage {
					t.Fatalf("decision must use the action's own evidence: %+v", decision)
				}
			})
		}
	}
}
