package moderation

import (
	"context"
	"fmt"
	"testing"
	"time"

	"antispambee/internal/detection"
)

func TestAdvertisingAutobanRequiresCorroborationAndRespectsPolicy(t *testing.T) {
	message := detection.SemanticMessageDetector
	profile := detection.SemanticProfileDetector
	confirmed := func(detector string) detection.Signal {
		signal := availableSignal(detector, .96, .96, 1)
		signal.EvidenceExcerpt = "Явное рекламное предложение из источника"
		return signal
	}
	for _, test := range []struct {
		name, text, primary, secondary, mode, member string
		elsewhere, allowlisted, disabled             bool
		want                                         ActionType
		verify                                       bool
	}{
		{name: "local proof", text: "Нужны люди для доставки заказов, оплата 13 000 рублей за смену. Интересны детали?", want: ActionBanUser},
		{name: "models agree", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, want: ActionBanUser, verify: true},
		{name: "models agree on profile", text: "Люблю магов", primary: profile, secondary: profile, want: ActionBanUser, verify: true},
		{name: "different scopes", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: profile, want: ActionReview, verify: true},
		{name: "no confirmation", text: "Сведу подкаст за 12 евро, пишите", primary: message, want: ActionReview, verify: true},
		{name: "false positive about a card pack", text: "Такой бред, что дают карты из события, если ты просто купил пак. Так они ещё и срезают этот срок до одной недели", primary: message, want: ActionReview, verify: true},
		{name: "other chat", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, elsewhere: true, want: ActionDeleteMessage},
		{name: "standard", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, mode: "STANDARD", want: ActionDeleteMessage, verify: true},
		{name: "ban disabled", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, disabled: true, want: ActionDeleteMessage, verify: true},
		{name: "administrator", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, member: "administrator", want: ActionReview},
		{name: "allowlist", text: "Сведу подкаст за 12 евро, пишите", primary: message, secondary: message, allowlisted: true, want: ActionReview},
	} {
		t.Run(test.name, func(t *testing.T) {
			mode := test.mode
			if mode == "" {
				mode = "STRICT"
			}
			banChat := int64(-1001)
			if test.elsewhere {
				banChat = -1002
			}
			model, verifier := &contentAnalyzerStub{}, &contentAnalyzerStub{}
			if test.primary != "" {
				model.signal = confirmed(test.primary)
			}
			if test.secondary != "" {
				verifier.signal = confirmed(test.secondary)
			}
			store := &recordingStore{}
			processor, err := NewProcessor(store, &profileFetcherStub{memberStatus: test.member}, detection.NewProfileDetector(),
				WithContentAnalyzer(model, &imageDownloaderStub{}, 0), WithAdvertisingAutoban(banChat, verifier),
				WithPolicyStore(&communityPolicyStub{policy: CommunityPolicy{
					ProtectionLevel: mode, AutomaticActionsEnabled: true, AutobanEnabled: !test.disabled, IsAllowlisted: test.allowlisted,
				}}))
			if err != nil {
				t.Fatal(err)
			}
			event := telegramEvent(fmt.Sprintf(`{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":%q}}`, test.text))
			if err := processor.Process(context.Background(), event); err != nil {
				t.Fatal(err)
			}
			if got := store.outcome.Decision.AuthorizedAction; got != test.want {
				t.Fatalf("decision = %s, want %s", got, test.want)
			}
			if called := verifier.input.Message.Text != ""; called != test.verify {
				t.Fatalf("called verifier = %t, want %t", called, test.verify)
			}
			if test.want == ActionBanUser {
				actions := store.outcome.Actions
				if len(actions) != 2 || actions[0].Type != ActionDeleteMessage || actions[1].Type != ActionBanUser {
					t.Fatalf("actions = %+v, want delete then ban", actions)
				}
			} else if test.want == ActionReview && len(store.outcome.Actions) != 0 {
				t.Fatalf("a review queued automatic actions: %+v", store.outcome.Actions)
			}
		})
	}
}

func TestContentOutageRetriesFreshUpdateAndReviewsOlderUpdate(t *testing.T) {
	store := &recordingStore{}
	model := &contentAnalyzerStub{signal: detection.Signal{
		Detector: detection.SemanticMessageDetector, Status: detection.StatusError,
		ReasonCodes: []string{detection.ReasonOpenRouterFailed, detection.ReasonOpenRouterTemporarilyUnavailable},
	}}
	processor, err := NewProcessor(store, &profileFetcherStub{}, detection.NewProfileDetector(), WithContentAnalyzer(model, &imageDownloaderStub{}, -1001))
	if err != nil {
		t.Fatal(err)
	}
	eventAt := func(at time.Time) string {
		return fmt.Sprintf(`{"message":{"message_id":7,"date":%d,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":"Привет"}}`, at.Unix())
	}
	if err := processor.Process(context.Background(), telegramEvent(eventAt(time.Now()))); err == nil || store.outcome.Decision.AuthorizedAction != "" {
		t.Fatalf("fresh outage must return a retry without committing: decision=%+v error=%v", store.outcome.Decision, err)
	}
	if err := processor.Process(context.Background(), telegramEvent(eventAt(time.Now().Add(-time.Minute)))); err != nil {
		t.Fatal(err)
	}
	if d := store.outcome.Decision; d.AuthorizedAction != ActionReview || d.AuthorizationReason != detection.ReasonOpenRouterFailed {
		t.Fatalf("old outage was not retained for review: %+v", d)
	}
}
