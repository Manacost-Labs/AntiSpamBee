package moderation

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"antispambee/internal/detection"
)

func TestCampaignIndicatorsMatchAliasesAndKeepDistinctLinks(t *testing.T) {
	key := []byte("test-key")
	first := campaignIndicators(key, detection.MessageContent{Text: "Напишите @Offer_Name", URLs: []string{"https://Example.net/path?utm_source=test&item=5"}}, "image-x")
	second := campaignIndicators(key, detection.MessageContent{URLs: []string{"telegram.me/offer_name", "http://example.net/path?item=5"}}, "image-x")
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("counts = %d/%d", len(first), len(second))
	}
	for i := range first {
		if first[i].Kind != second[i].Kind || !bytes.Equal(first[i].Fingerprint, second[i].Fingerprint) {
			t.Fatalf("equivalent source %d did not match", i)
		}
	}
	third := campaignIndicators(key, detection.MessageContent{URLs: []string{"example.net/path?item=6"}}, "")
	if len(third) != 1 || bytes.Equal(first[2].Fingerprint, third[0].Fingerprint) {
		t.Fatal("distinct deals were merged")
	}
}

type campaignStoreStub struct{}

func (campaignStoreStub) ObserveCampaign(context.Context, string, ActionTarget, []CampaignIndicator, bool) ([]string, error) {
	return []string{"contact"}, nil
}

func TestCampaignMatchQueuesReviewAndNeverEnforcement(t *testing.T) {
	store := &recordingStore{}
	p, err := NewProcessor(store, &profileFetcherStub{}, detection.NewProfileDetector(),
		WithModerationOperations(-1001, []byte("key"), campaignStoreStub{}),
		WithPolicyStore(&communityPolicyStub{policy: CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, ModeratorChatID: 91}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Process(context.Background(), telegramEvent(`{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":"Привет, @offer_name"}}`)); err != nil {
		t.Fatal(err)
	}
	if out := store.outcome; !out.QueueReview || out.Decision.AuthorizationReason != ReasonRepeatedCampaign || len(out.Actions) != 0 || out.Evidence.Policy.ModeratorChatID != 91 {
		t.Fatalf("outcome = %+v", out)
	}
}

type callbackStoreStub struct {
	commandStoreStub
	resolved bool
}

func (s *callbackStoreStub) PendingReviewForModerator(_ context.Context, _, _ string, id int64) (ReviewCase, bool, error) {
	return ReviewCase{Target: ActionTarget{ChatID: -1001}}, id == 42 && !s.resolved, nil
}

func (s *callbackStoreStub) ResolveReview(_ context.Context, _, _ string, _ int64, spam bool) (bool, error) {
	if !spam || s.resolved {
		return false, fmt.Errorf("unexpected duplicate/wrong decision")
	}
	s.resolved = true
	return true, nil
}

type callbackClientStub struct {
	commandTelegramStub
	answers []string
}

func (c *callbackClientStub) AnswerCallbackQuery(_ context.Context, _, answer string) error {
	c.answers = append(c.answers, answer)
	return nil
}

func TestReviewCallbackRejectsOthersAndIsIdempotent(t *testing.T) {
	store := &callbackStoreStub{}
	client := &callbackClientStub{commandTelegramStub: commandTelegramStub{status: "administrator"}}
	p, err := NewProcessor(&recordingStore{}, &profileFetcherStub{}, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewCommandRouter(store, client, p, 0, "valid_bot")
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		id       int
		kind     string
		accepted bool
	}{{42, "group", false}, {43, "private", false}, {42, "private", true}, {42, "private", true}} {
		payload := fmt.Sprintf(`{"callback_query":{"id":"callback","from":{"id":%d},"message":{"chat":{"id":%d,"type":%q}},"data":"review:spam:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}}`, attempt.id, attempt.id, attempt.kind)
		if err := router.Process(context.Background(), telegramEvent(payload)); err != nil {
			t.Fatal(err)
		}
		if store.resolved != attempt.accepted {
			t.Fatalf("unexpected moderator effect for %+v", attempt)
		}
	}
	if len(client.answers) != 4 || client.answers[2] == client.answers[3] {
		t.Fatalf("callback acknowledgments = %q", client.answers)
	}
}
