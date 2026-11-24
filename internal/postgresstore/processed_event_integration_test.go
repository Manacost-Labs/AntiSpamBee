package postgresstore

import (
	"context"
	"os"
	"testing"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/moderation"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreRecognizesOnlyCommittedModerationIdentity(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := events.NewTelegramIdentity(123456, 900001)
	if err != nil {
		t.Fatal(err)
	}
	event := events.TelegramUpdate{SchemaVersion: "1", TenantID: "9d83e552-8910-4c46-b55a-63074078829e", EventID: identity.EventID, SourceKey: identity.SourceKey, BotID: 123456, UpdateID: 900001}
	// These tests are opt-in and run against an isolated test database.
	if _, err := pool.Exec(ctx, "DELETE FROM moderation_events WHERE event_id=$1", event.EventID); err != nil {
		t.Fatal(err)
	}
	check := func(event events.TelegramUpdate, want bool) {
		t.Helper()
		got, err := store.ModerationEventProcessed(ctx, event)
		if err != nil || got != want {
			t.Fatalf("processed(%+v) = %v, %v; want %v", event, got, err, want)
		}
	}
	check(event, false)
	score, confidence := .95, .99
	outcome := moderation.Outcome{
		State:    moderation.DecidedPendingAction,
		Decision: moderation.Decision{RiskScore: .95, DecisionConfidence: .99, EvidenceCoverage: 1, RecommendedAction: moderation.ActionDeleteMessage, AuthorizedAction: moderation.ActionDeleteMessage, AuthorizationReason: moderation.ReasonLikelyAdvertising},
		Actions:  []moderation.ActionRequest{{Type: moderation.ActionDeleteMessage, Target: moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: -100777, UserID: 42, MessageID: 123}, IdempotencyKey: "processed-event-test:" + event.EventID}},
		Signals:  []detection.Signal{{SchemaVersion: "1", Detector: "message.advertising", DetectorVersion: "test-v1", Category: "spam.message", Status: detection.StatusAvailable, Score: &score, Confidence: &confidence, Severity: detection.SeverityHigh, EvidenceCoverage: 1, ReasonCodes: []string{detection.ReasonCommercialPromotion}, MatchedRules: []string{"TEST_OFFER"}, CreatedAt: time.Now().UTC()}},
	}
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatal(err)
	}
	check(event, true) // Pending action does not require repeating enrichment.
	for _, mutate := range []func(*events.TelegramUpdate){
		func(e *events.TelegramUpdate) { e.EventID = "82373d0f-5740-5f07-b4e8-02c2f4edd824" },
		func(e *events.TelegramUpdate) { e.TenantID = "0cfbc1da-0db1-4fdf-93fc-f47835b33100" },
		func(e *events.TelegramUpdate) { e.SourceKey += ":other" },
		func(e *events.TelegramUpdate) { e.BotID++ },
		func(e *events.TelegramUpdate) { e.UpdateID++ },
		func(e *events.TelegramUpdate) { e.SchemaVersion = "2" },
	} {
		other := event
		mutate(&other)
		check(other, false)
	}
	if _, err := pool.Exec(ctx, "UPDATE moderation_decisions SET authorization_reason=$2 WHERE event_id=$1", event.EventID, moderation.ReasonModeratorCommand); err != nil {
		t.Fatal(err)
	}
	check(event, false) // Router must still retry delivery of command replies.
	if _, err := pool.Exec(ctx, "DELETE FROM moderation_decisions WHERE event_id=$1", event.EventID); err != nil {
		t.Fatal(err)
	}
	check(event, false) // An event row without a decision cannot suppress work.
}
