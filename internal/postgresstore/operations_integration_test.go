package postgresstore

import (
	"context"
	"testing"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/moderation"
)

func TestOperationsAlertCooldownSurvivesWorkerRestart(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	const group = int64(-100609994)
	const kind = "classification"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM moderation_operation_alerts WHERE chat_id=$1`, group) })

	// Separate workers can see the same incident at the same time.
	restarted := &Store{pool: pool}
	type reservation struct {
		until time.Time
		err   error
	}
	results := make(chan reservation, 2)
	for _, worker := range []*Store{store, restarted} {
		go func() {
			until, err := worker.ReserveOperationsAlert(ctx, group, kind, 15*time.Minute)
			results <- reservation{until, err}
		}()
	}
	var reserved time.Time
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		if !result.until.IsZero() {
			if !reserved.IsZero() {
				t.Fatal("both workers reserved the same alert")
			}
			reserved = result.until
		}
	}
	if reserved.IsZero() {
		t.Fatal("no worker reserved the alert")
	}
	if until, err := restarted.ReserveOperationsAlert(ctx, group, "queue_slow", 15*time.Minute); err != nil || until.IsZero() {
		t.Fatalf("another alert type was blocked: until=%v err=%v", until, err)
	}
	if err := restarted.RescheduleOperationsAlert(ctx, group, kind, reserved.Add(-time.Minute), 0); err != nil {
		t.Fatal(err)
	}
	if until, err := restarted.ReserveOperationsAlert(ctx, group, kind, 15*time.Minute); err != nil || !until.IsZero() {
		t.Fatalf("a stale reservation changed the cooldown: until=%v err=%v", until, err)
	}
	if err := store.RescheduleOperationsAlert(ctx, group, kind, reserved, 0); err != nil {
		t.Fatal(err)
	}
	if until, err := restarted.ReserveOperationsAlert(ctx, group, kind, 15*time.Minute); err != nil || until.IsZero() {
		t.Fatalf("alert not reserved after rescheduled cooldown: until=%v err=%v", until, err)
	}
}

func TestTechnicalOutageStaysInMonitoringAndCannotBeActedOnAsSpam(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	const group, moderator = int64(-100609993), int64(70008)
	event := commandTestEvent(t, 901091)
	if _, err := pool.Exec(ctx, `DELETE FROM moderation_events WHERE event_id=$1`, event.EventID); err != nil {
		t.Fatal(err)
	}
	if err := setCommunityModerator(ctx, pool, event.TenantID, group, moderator); err != nil {
		t.Fatal(err)
	}
	outcome := moderation.Outcome{
		State: moderation.ProcessedReview, QueueReview: true,
		Decision: moderation.Decision{RecommendedAction: moderation.ActionReview, AuthorizedAction: moderation.ActionReview, AuthorizationReason: detection.ReasonOpenRouterFailed},
		Evidence: &moderation.Evidence{Target: moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: group, UserID: 44, MessageID: 62},
			Policy: moderation.CommunityPolicy{ModeratorChatID: moderator}},
		Signals: []detection.Signal{{SchemaVersion: "1", Detector: detection.SemanticMessageDetector, DetectorVersion: "outage-test", Category: "spam.advertising",
			Status: detection.StatusError, Severity: detection.SeverityInfo, ReasonCodes: []string{detection.ReasonOpenRouterFailed}, CreatedAt: time.Now()}},
	}
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatal(err)
	}
	var cards int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM moderation_reviews WHERE event_id=$1`, event.EventID).Scan(&cards); err != nil || cards != 0 {
		t.Fatalf("technical review generated cards=%d err=%v", cards, err)
	}
	status, err := store.OperationsStatus(ctx, group)
	if err != nil || status.ModelErrors != 1 {
		t.Fatalf("operations status=%+v err=%v", status, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO moderation_reviews(event_id) VALUES ($1)`, event.EventID); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.PendingReviewForModerator(ctx, event.TenantID, event.EventID, moderator); err != nil || found {
		t.Fatalf("old technical card still active=%t err=%v", found, err)
	}
	if accepted, err := store.ResolveReview(ctx, event.TenantID, event.EventID, moderator, true); err != nil || accepted {
		t.Fatalf("old technical card can delete=%t err=%v", accepted, err)
	}
}

func TestReviewDecisionPersistsLabelAndQueuesOnlyOneManualDelete(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	const group, moderator = int64(-100609991), int64(70007)
	for index, spam := range []bool{false, true} {
		event := commandTestEvent(t, 901080+int64(index))
		if _, err := pool.Exec(ctx, `DELETE FROM moderation_events WHERE event_id=$1`, event.EventID); err != nil {
			t.Fatal(err)
		}
		if err := setCommunityModerator(ctx, pool, event.TenantID, group, moderator); err != nil {
			t.Fatal(err)
		}
		target := moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: group, UserID: 5432, MessageID: 880 + int64(index)}
		score, confidence := .90, .40
		outcome := moderation.Outcome{
			State: moderation.ProcessedReview, QueueReview: true,
			Decision: moderation.Decision{RiskScore: score, DecisionConfidence: confidence, RecommendedAction: moderation.ActionReview,
				AuthorizedAction: moderation.ActionReview, AuthorizationReason: moderation.ReasonInsufficientEvidence},
			Evidence: &moderation.Evidence{Target: target, Policy: moderation.CommunityPolicy{ModeratorChatID: moderator}, Message: detection.MessageContent{Text: "Пришлите подробности"}},
			Signals: []detection.Signal{{SchemaVersion: "1", Detector: "model.test", DetectorVersion: "v1", Category: "spam.advertising",
				Status: detection.StatusAvailable, Score: &score, Confidence: &confidence, Severity: detection.SeverityMedium, CreatedAt: time.Now()}},
		}
		if err := store.RecordTerminal(ctx, event, outcome); err != nil {
			t.Fatal(err)
		}
		if err := store.RecordTerminal(ctx, event, outcome); err != nil {
			t.Fatal(err)
		}
		var outboxCount int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM moderation_command_reply_outbox WHERE event_id=$1 AND payload->>'review_event_id'=$1::text`, event.EventID).Scan(&outboxCount); err != nil || outboxCount != 1 {
			t.Fatalf("review outbox rows=%d err=%v", outboxCount, err)
		}
		if _, found, err := store.PendingReviewForModerator(ctx, event.TenantID, event.EventID, moderator+1); err != nil || found {
			t.Fatalf("wrong moderator found=%v err=%v", found, err)
		}
		if review, found, err := store.PendingReviewForModerator(ctx, event.TenantID, event.EventID, moderator); err != nil || !found || review.Target != target {
			t.Fatalf("assigned moderator review=%+v found=%v err=%v", review, found, err)
		}
		if ok, err := store.ResolveReview(ctx, event.TenantID, event.EventID, moderator+1, spam); err != nil || ok {
			t.Fatalf("wrong moderator resolved=%v err=%v", ok, err)
		}
		if ok, err := store.ResolveReview(ctx, event.TenantID, event.EventID, moderator, spam); err != nil || !ok {
			t.Fatalf("resolve=%v err=%v", ok, err)
		}
		if ok, err := store.ResolveReview(ctx, event.TenantID, event.EventID, moderator, !spam); err != nil || ok {
			t.Fatalf("repeat changed outcome=%v err=%v", ok, err)
		}
		var verdict string
		var actions int
		if err := pool.QueryRow(ctx, `SELECT verdict,(SELECT count(*) FROM moderation_actions WHERE event_id=$1 AND manual_review)
			FROM moderation_reviews WHERE event_id=$1`, event.EventID).Scan(&verdict, &actions); err != nil {
			t.Fatal(err)
		}
		if (!spam && (actions != 0 || verdict != "KEEP")) || (spam && (actions != 1 || verdict != "SPAM")) {
			t.Fatalf("spam=%v verdict=%s actions=%d", spam, verdict, actions)
		}
		if spam {
			if _, err := pool.Exec(ctx, `UPDATE moderation_actions SET next_attempt_at='1999-01-01' WHERE event_id=$1`, event.EventID); err != nil {
				t.Fatal(err)
			}
			action, found, err := store.ClaimAction(ctx, "review-test", time.Minute)
			if err != nil || !found || action.EventID != event.EventID || action.Type != moderation.ActionDeleteMessage || action.AuthorizationReason != moderation.ReasonModeratorCommand {
				t.Fatalf("manual action=%+v found=%v err=%v", action, found, err)
			}
			if err := store.MarkActionSucceeded(ctx, action, false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(ctx, `DELETE FROM moderation_command_reply_outbox WHERE event_id=$1`, event.EventID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCampaignRequiresRecentConfirmedAdvertisementFromAnotherAuthor(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	tenant := commandTestEvent(t, 901090).TenantID
	const group = int64(-100609992)
	if _, err := pool.Exec(ctx, `DELETE FROM moderation_campaign_observations WHERE chat_id=$1`, group); err != nil {
		t.Fatal(err)
	}
	indicators := []moderation.CampaignIndicator{{Kind: "contact", Fingerprint: []byte("fixture-digest")}}
	for _, test := range []struct {
		user, message   int64
		confirmed, want bool
	}{{42, 1, false, false}, {43, 2, false, false}, {42, 3, true, false}, {42, 4, false, false}, {43, 5, false, true}} {
		target := moderation.ActionTarget{ChatID: group, UserID: test.user, MessageID: test.message}
		kinds, err := store.ObserveCampaign(ctx, tenant, target, indicators, test.confirmed)
		if err != nil || (len(kinds) > 0) != test.want {
			t.Fatalf("match for %+v = %v/%v", test, kinds, err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE moderation_campaign_observations SET observed_at=now()-interval '46 minutes' WHERE chat_id=$1`, group); err != nil {
		t.Fatal(err)
	}
	if kinds, err := store.ObserveCampaign(ctx, tenant, moderation.ActionTarget{ChatID: group, UserID: 43, MessageID: 6}, indicators, false); err != nil || len(kinds) > 0 {
		t.Fatalf("expired campaign matched: %v/%v", kinds, err)
	}
}
