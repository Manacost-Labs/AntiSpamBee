package moderation

import (
	"testing"

	"antispambee/internal/detection"
)

func TestAutomaticSafetyBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content bool
		signals []detection.Signal
		want    ActionType
	}{
		{"profile only", true, []detection.Signal{availableSignal("profile.personal_channel", 1, .95, 1)}, ActionReview},
		{"model without message", false, []detection.Signal{availableSignal("model.jev_advertising", .92, .96, .5)}, ActionReview},
		{"past violations only", true, []detection.Signal{availableSignal("behavior.spam", 1, .95, 1)}, ActionReview},
		{"correlated signals cannot ban", true, []detection.Signal{availableSignal("message.commercial_promotion", .95, .95, 1), availableSignal("model.jev_advertising", .96, .96, 1)}, ActionDeleteMessage},
		{"explicit message still deleted", true, []detection.Signal{availableSignal("message.commercial_promotion", 1, .95, 1)}, ActionDeleteMessage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDecisionEngine().Decide(DecisionInput{Target: ActionTarget{Kind: TargetMessage, ChatID: -1, UserID: 7, MessageID: 9}, HasMessageContent: tc.content, Signals: tc.signals})
			if d.AuthorizedAction != tc.want {
				t.Fatalf("decision=%+v want %s", d, tc.want)
			}
		})
	}
}
