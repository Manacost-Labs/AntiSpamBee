package moderation

import (
	"context"
	"testing"

	"antispambee/internal/detection"
)

func TestProhibitedChannelBanAuthorization(t *testing.T) {
	for _, reason := range []string{detection.ReasonConfirmedAdultChannel, detection.ReasonConfirmedFraudChannel} {
		for _, tc := range []struct {
			name                                                  string
			strict, protected, disabled, autobanDisabled, unknown bool
			score, confidence, coverage                           float64
			detector, excerpt                                     string
			want                                                  ActionType
		}{
			{"confirmed", true, false, false, false, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionBanUser},
			{"standard", false, false, false, false, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"protected", true, true, false, false, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"actions disabled", true, false, true, false, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"autoban disabled", true, false, false, true, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionDeleteMessage},
			{"unknown sender", true, false, false, false, true, 1, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"weak score", true, false, false, false, false, .97, .99, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"weak confidence", true, false, false, false, false, 1, .97, 1, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"partial evidence", true, false, false, false, false, 1, .99, .75, detection.ProhibitedChannelDetectorName, "channel evidence", ActionReview},
			{"no excerpt", true, false, false, false, false, 1, .99, 1, detection.ProhibitedChannelDetectorName, "", ActionReview},
			{"untrusted detector", true, false, false, false, false, 1, .99, 1, "model.some_model", "channel evidence", ActionReview},
		} {
			t.Run(reason+"/"+tc.name, func(t *testing.T) {
				signal := availableSignal(tc.detector, tc.score, tc.confidence, tc.coverage)
				signal.ReasonCodes, signal.EvidenceExcerpt = []string{reason}, tc.excerpt
				decision := NewDecisionEngine().Decide(DecisionInput{
					Target:  ActionTarget{Kind: TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
					Signals: []detection.Signal{signal}, AllowAdvertisingChannelDeletion: tc.strict,
					IsProtected: tc.protected, AutomaticActionsDisabled: tc.disabled,
					AutobanDisabled: tc.autobanDisabled, UnverifiedSender: tc.unknown,
				})
				if decision.AuthorizedAction != tc.want {
					t.Fatalf("decision = %+v, want %s", decision, tc.want)
				}
				if tc.want == ActionBanUser && decision.AuthorizationReason != reason {
					t.Fatalf("authorization reason = %s, want %s", decision.AuthorizationReason, reason)
				}
			})
		}
	}
}

func TestProcessorBansProhibitedChannelWithOrdinaryMessage(t *testing.T) {
	for _, tc := range []struct {
		name, description, reason string
		title                     string
		posts                     []string
	}{
		{name: "adult", description: "Эротические фото и интимные видео", reason: detection.ReasonConfirmedAdultChannel},
		{name: "fraud", description: "Удвою твои деньги. Переведи депозит, пиши в лс", reason: detection.ReasonConfirmedFraudChannel},
		{name: "message 54888", title: "Мой секрет 😘", reason: detection.ReasonConfirmedAdultChannel,
			posts: []string{"🎥 Без цензуры и ограничений — заявка открывает доступ\n👉 https://t.me/+exampleInvite", "", ""}},
		{name: "message 58872", title: "Приват Милфы", reason: detection.ReasonConfirmedAdultChannel,
			posts: []string{"🔥ОПЫТНАЯ МАМОЧКА РАЗДЕЛАСЬ НА КАМЕРУ ТУТ👉https://t.me/+exampleInvite", ""}},
	} {
		for _, status := range []string{"member", "administrator", "creator"} {
			t.Run(tc.name+"/"+status, func(t *testing.T) {
				store := &recordingStore{}
				posts := tc.posts
				if posts == nil {
					posts = []string{"", "Доброе утро", ""}
				}
				fetcher := &profileFetcherStub{
					profile: detection.Profile{PersonalChannel: &detection.PersonalChannel{
						Title: tc.title, Description: tc.description, RecentPosts: posts,
					}}, memberStatus: status,
				}
				processor, err := NewProcessor(store, fetcher, detection.NewProfileDetector(), WithPolicyStore(&communityPolicyStub{
					policy: CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true},
				}))
				if err != nil {
					t.Fatal(err)
				}
				err = processor.Process(context.Background(), telegramEvent(`{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":"Привет всем"}}`))
				if err != nil {
					t.Fatal(err)
				}
				wantBan := status == "member"
				if hasAction(store.outcome, ActionBanUser) != wantBan || hasAction(store.outcome, ActionDeleteMessage) != wantBan {
					t.Fatalf("unexpected actions: %+v", store.outcome)
				}
				if wantBan && (store.outcome.Evidence == nil || store.outcome.Decision.AuthorizationReason != tc.reason) {
					t.Fatalf("missing ban evidence or reason: %+v", store.outcome)
				}
			})
		}
	}
}
