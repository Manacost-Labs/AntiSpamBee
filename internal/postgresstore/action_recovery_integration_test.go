package postgresstore

import (
	"context"
	"testing"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/moderation"
)

func TestPairedAdvertisingActionsRecoverLeasesAndPreserveBanFailure(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	event := commandTestEvent(t, 432011)
	score, confidence := .96, .96
	target := moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: -1001345, UserID: 72, MessageID: 18}
	if err := store.RecordTerminal(ctx, event, moderation.Outcome{
		State: moderation.DecidedPendingAction,
		Decision: moderation.Decision{RiskScore: .96, DecisionConfidence: .96, EvidenceCoverage: 1,
			RecommendedAction: moderation.ActionBanUser, AuthorizedAction: moderation.ActionBanUser,
			AuthorizationReason: moderation.ReasonConfirmedAdvertisingAutoban},
		Signals: []detection.Signal{{
			SchemaVersion: "1", Detector: "message.test", DetectorVersion: "v1", Category: "spam.advertising",
			Status: detection.StatusAvailable, Score: &score, Confidence: &confidence, Severity: detection.SeverityHigh,
			EvidenceCoverage: 1, CreatedAt: time.Now(),
		}},
		Actions: []moderation.ActionRequest{
			{Type: moderation.ActionDeleteMessage, Target: target, IdempotencyKey: "delete-432011"},
			{Type: moderation.ActionBanUser, Target: target, IdempotencyKey: "ban-432011"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var reasons, rules int
	if err := pool.QueryRow(ctx, `SELECT cardinality(reason_codes), cardinality(matched_rules) FROM detector_signals WHERE event_id=$1`, event.EventID).Scan(&reasons, &rules); err != nil || reasons != 0 || rules != 0 {
		t.Fatalf("empty evidence lists = %d/%d/%v", reasons, rules, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE moderation_actions SET next_attempt_at = CASE action_type
		WHEN 'BAN_USER' THEN '2000-01-01'::timestamptz ELSE '2000-01-02'::timestamptz END WHERE event_id=$1`, event.EventID); err != nil {
		t.Fatal(err)
	}
	claim := func(want moderation.ActionType) moderation.ClaimedAction {
		t.Helper()
		action, found, err := store.ClaimAction(ctx, "restarting-worker", time.Minute)
		if err != nil || !found || action.EventID != event.EventID || action.Type != want {
			t.Fatalf("claim = %+v/%t/%v, want %s", action, found, err, want)
		}
		return action
	}
	state := func(want string) {
		t.Helper()
		var got string
		if err := pool.QueryRow(ctx, `SELECT terminal_state FROM moderation_events WHERE event_id=$1`, event.EventID).Scan(&got); err != nil || got != want {
			t.Fatalf("state = %s/%v, want %s", got, err, want)
		}
	}
	oldBan := claim(moderation.ActionBanUser)
	if _, err := pool.Exec(ctx, `UPDATE moderation_actions SET lease_until=now()-interval '1 second' WHERE action_id=$1`, oldBan.ActionID); err != nil {
		t.Fatal(err)
	}
	currentBan := claim(moderation.ActionBanUser)
	if currentBan.AttemptCount != oldBan.AttemptCount+1 {
		t.Fatal("did not get a new lease attempt")
	}
	if err := store.MarkActionRetryable(ctx, oldBan, time.Now(), "stale retry"); err == nil {
		t.Fatal("stale attempt was allowed to release the new lease")
	}
	if err := store.MarkActionSucceeded(ctx, oldBan, false); err == nil {
		t.Fatal("stale attempt was allowed to complete the new lease")
	}
	if err := store.MarkActionPermanentFailure(ctx, currentBan, "Telegram rejected ban"); err != nil {
		t.Fatal(err)
	}
	state(string(moderation.DecidedPendingAction))
	if err := store.MarkActionSucceeded(ctx, claim(moderation.ActionDeleteMessage), false); err != nil {
		t.Fatal(err)
	}
	state("DEAD_LETTER")
}
