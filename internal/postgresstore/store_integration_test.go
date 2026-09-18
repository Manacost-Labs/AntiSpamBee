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

func TestStoreRecordTerminalIsIdempotent(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, "TRUNCATE user_reports, moderation_allowlist, community_policies, message_activity, moderation_audit_log, moderation_actions, moderation_decisions, detector_signals, moderation_events"); err != nil {
		t.Fatalf("truncate moderation_events: %v", err)
	}

	store, err := New(pool)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}

	event := events.TelegramUpdate{
		SchemaVersion: "1",
		TenantID:      "9d83e552-8910-4c46-b55a-63074078829e",
		EventID:       "82373d0f-5740-5f07-b4e8-02c2f4edd824",
		SourceKey:     "telegram:123456:789",
		BotID:         123456,
		UpdateID:      789,
	}

	score := 0.92
	messageScore := 0.95
	jevScore := 0.97
	jevConfidence := 0.91
	confidence := 0.95
	outcome := moderation.Outcome{
		State: moderation.DecidedPendingAction,
		Decision: moderation.Decision{
			RiskScore:           0.95,
			DecisionConfidence:  0.95,
			EvidenceCoverage:    1,
			RecommendedAction:   moderation.ActionDeleteMessage,
			AuthorizedAction:    moderation.ActionDeleteMessage,
			AuthorizationReason: moderation.ReasonLikelyAdvertising,
		},
		Action: &moderation.ActionRequest{
			Type: moderation.ActionDeleteMessage,
			Target: moderation.ActionTarget{
				Kind: moderation.TargetMessage, ChatID: -100777, UserID: 42, MessageID: 91,
			},
			IdempotencyKey: "delete-message:-100777:91:82373d0f-5740-5f07-b4e8-02c2f4edd824",
		},
		Signals: []detection.Signal{
			{
				SchemaVersion:    "1",
				Detector:         "profile.personal_channel",
				DetectorVersion:  "profile-v3",
				Category:         "spam.profile",
				Status:           detection.StatusAvailable,
				Score:            &score,
				Confidence:       &confidence,
				Severity:         detection.SeverityHigh,
				EvidenceCoverage: 0.75,
				ReasonCodes:      []string{detection.ReasonMassJobOffer, detection.ReasonAdvertisingChannel},
				MatchedRules:     []string{"PROFILE_JOB_01", "PROFILE_JOB_02", "PROFILE_JOB_04"},
				CreatedAt:        time.Date(2026, 9, 15, 19, 0, 0, 0, time.UTC),
			},
			{
				SchemaVersion:    "1",
				Detector:         "message.commercial_promotion",
				DetectorVersion:  "message-ad-v2",
				Category:         "spam.advertising",
				Status:           detection.StatusAvailable,
				Score:            &messageScore,
				Confidence:       &confidence,
				Severity:         detection.SeverityHigh,
				EvidenceCoverage: 1,
				ReasonCodes:      []string{detection.ReasonCommercialPromotion, detection.ReasonVPNPromotion},
				MatchedRules:     []string{"MESSAGE_AD_VPN_01"},
				CreatedAt:        time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC),
			},
			{
				SchemaVersion:    "1",
				Detector:         "model.jev_advertising",
				DetectorVersion:  "jev-openrouter-v1",
				Category:         "spam.advertising",
				Status:           detection.StatusAvailable,
				Score:            &jevScore,
				Confidence:       &jevConfidence,
				Severity:         detection.SeverityHigh,
				EvidenceCoverage: 1,
				ReasonCodes:      []string{detection.ReasonCommercialPromotion, detection.ReasonGamblingPromotion},
				MatchedRules:     []string{"JEV_CATEGORY_GAMBLING", "JEV_PROHIBITED_AD_01"},
				CreatedAt:        time.Date(2026, 9, 18, 12, 1, 0, 0, time.UTC),
			},
		},
	}
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatalf("record terminal event: %v", err)
	}
	replayedJevScore := 0.96
	outcome.Signals[2].Score = &replayedJevScore
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatalf("record replayed terminal event: %v", err)
	}

	var (
		count    int
		tenantID string
		state    string
	)
	if err := pool.QueryRow(ctx, `
		SELECT count(*), min(tenant_id::text), min(terminal_state)
		FROM moderation_events
		WHERE source_key = $1
	`, event.SourceKey).Scan(&count, &tenantID, &state); err != nil {
		t.Fatalf("query recorded event: %v", err)
	}

	if count != 1 {
		t.Fatalf("recorded row count = %d, want 1", count)
	}
	if tenantID != event.TenantID {
		t.Errorf("tenant ID = %q, want %q", tenantID, event.TenantID)
	}
	if state != string(moderation.DecidedPendingAction) {
		t.Errorf("terminal state = %q, want %q", state, moderation.DecidedPendingAction)
	}

	var (
		signalCount int
		status      string
		storedScore float64
		reasons     []string
	)
	if err := pool.QueryRow(ctx, `
		SELECT count(*) OVER (), status, score, reason_codes
		FROM detector_signals
		WHERE event_id = $1 AND detector = 'message.commercial_promotion'
		LIMIT 1
	`, event.EventID).Scan(&signalCount, &status, &storedScore, &reasons); err != nil {
		t.Fatalf("query detector signal: %v", err)
	}
	if signalCount != 1 || status != string(detection.StatusAvailable) || storedScore != messageScore {
		t.Errorf("signal count = %d, status = %q, score = %v", signalCount, status, storedScore)
	}
	if len(reasons) != 2 {
		t.Errorf("reason codes = %v", reasons)
	}
	var totalSignals int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM detector_signals WHERE event_id = $1
	`, event.EventID).Scan(&totalSignals); err != nil {
		t.Fatalf("count detector signals: %v", err)
	}
	if totalSignals != 3 {
		t.Errorf("total detector signals = %d, want 3", totalSignals)
	}
	var storedJevScore float64
	if err := pool.QueryRow(ctx, `
		SELECT score FROM detector_signals
		WHERE event_id = $1 AND detector = 'model.jev_advertising'
	`, event.EventID).Scan(&storedJevScore); err != nil {
		t.Fatalf("query Jev detector signal: %v", err)
	}
	if storedJevScore != jevScore {
		t.Errorf("stored Jev score = %v, want first result %v", storedJevScore, jevScore)
	}
	var actionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM moderation_actions WHERE event_id = $1`, event.EventID).Scan(&actionCount); err != nil {
		t.Fatalf("count moderation actions: %v", err)
	}
	if actionCount != 1 {
		t.Errorf("action count = %d, want 1", actionCount)
	}

	claimed, found, err := store.ClaimAction(ctx, "worker-1", 30*time.Second)
	if err != nil || !found {
		t.Fatalf("ClaimAction() = %#v, %v, %v", claimed, found, err)
	}
	if claimed.Type != moderation.ActionDeleteMessage || claimed.AttemptCount != 1 {
		t.Fatalf("claimed action = %#v", claimed)
	}
	if _, found, err := store.ClaimAction(ctx, "worker-2", 30*time.Second); err != nil || found {
		t.Fatalf("second ClaimAction() found/error = %v/%v, want leased action hidden", found, err)
	}
	if err := store.MarkActionRetryable(ctx, claimed, time.Now().Add(-time.Second), "temporary failure"); err != nil {
		t.Fatalf("MarkActionRetryable() error = %v", err)
	}
	claimed, found, err = store.ClaimAction(ctx, "worker-2", 30*time.Second)
	if err != nil || !found || claimed.AttemptCount != 2 {
		t.Fatalf("reclaimed action = %#v, %v, %v", claimed, found, err)
	}
	if err := store.MarkActionSucceeded(ctx, claimed, false); err != nil {
		t.Fatalf("MarkActionSucceeded() error = %v", err)
	}
	var actionStatus, finalEventState string
	if err := pool.QueryRow(ctx, `
		SELECT a.status, e.terminal_state
		FROM moderation_actions a
		JOIN moderation_events e ON e.event_id = a.event_id
		WHERE a.event_id = $1
	`, event.EventID).Scan(&actionStatus, &finalEventState); err != nil {
		t.Fatalf("query completed action: %v", err)
	}
	if actionStatus != "SUCCEEDED" || finalEventState != string(moderation.ProcessedAction) {
		t.Fatalf("action/event status = %q/%q", actionStatus, finalEventState)
	}
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatalf("record event replay after completed action: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT terminal_state FROM moderation_events WHERE event_id = $1`, event.EventID).Scan(&finalEventState); err != nil {
		t.Fatal(err)
	}
	if finalEventState != string(moderation.ProcessedAction) {
		t.Fatalf("replayed event state = %q, want completed action preserved", finalEventState)
	}
	outcome.Decision.RiskScore = 1
	outcome.Decision.RecommendedAction = moderation.ActionBanUser
	outcome.Decision.AuthorizedAction = moderation.ActionBanUser
	outcome.Action.Type = moderation.ActionBanUser
	outcome.Action.IdempotencyKey = "ban:-100777:42:82373d0f-5740-5f07-b4e8-02c2f4edd824"
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatalf("record changed replayed decision: %v", err)
	}
	var storedActionType string
	if err := pool.QueryRow(ctx, `SELECT count(*), min(action_type) FROM moderation_actions WHERE event_id = $1`, event.EventID).Scan(&actionCount, &storedActionType); err != nil {
		t.Fatal(err)
	}
	if actionCount != 1 || storedActionType != string(moderation.ActionDeleteMessage) {
		t.Fatalf("changed replay created action: count/type = %d/%q", actionCount, storedActionType)
	}
}

func TestStoreObserveMessageCountsDuplicateAndFlood(t *testing.T) {
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
	if _, err := pool.Exec(ctx, "TRUNCATE message_activity CASCADE"); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	target := moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: -1001, UserID: 42, MessageID: 1}
	content := detection.MessageContent{Text: "одинаковая реклама"}
	ids := []string{
		"00000000-0000-4000-8000-000000000001",
		"00000000-0000-4000-8000-000000000002",
		"00000000-0000-4000-8000-000000000003",
		"00000000-0000-4000-8000-000000000004",
		"00000000-0000-4000-8000-000000000005",
	}
	var stats detection.BehaviorStats
	for index, id := range ids {
		target.MessageID = int64(index + 1)
		stats, err = store.ObserveMessage(ctx, events.TelegramUpdate{
			EventID: id, TenantID: "9d83e552-8910-4c46-b55a-63074078829e",
		}, target, content)
		if err != nil {
			t.Fatal(err)
		}
	}
	if stats.DuplicateCount != 5 || stats.MessagesInWindow != 5 {
		t.Fatalf("behavior stats = %#v", stats)
	}
}

func TestStorePersistsCommunityPolicyAllowlistAndReportIdempotently(t *testing.T) {
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
	if _, err := pool.Exec(ctx, "TRUNCATE user_reports, moderation_allowlist, community_policies"); err != nil {
		t.Fatal(err)
	}
	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	tenantID := "9d83e552-8910-4c46-b55a-63074078829e"
	if err := store.SetCommunityProtection(ctx, tenantID, -1001, "OBSERVE"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAllowlisted(ctx, tenantID, -1001, 42, 1, true); err != nil {
		t.Fatal(err)
	}
	policy, err := store.GetCommunityPolicy(ctx, tenantID, -1001, 42)
	if err != nil {
		t.Fatal(err)
	}
	if policy.ProtectionLevel != "OBSERVE" || policy.AutomaticActionsEnabled || policy.AutobanEnabled || !policy.IsAllowlisted {
		t.Fatalf("policy = %#v", policy)
	}
	for range 2 {
		if err := store.RecordUserReport(ctx, tenantID, -1001, 7, 42, 99); err != nil {
			t.Fatal(err)
		}
	}
	var reportCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM user_reports").Scan(&reportCount); err != nil {
		t.Fatal(err)
	}
	if reportCount != 1 {
		t.Fatalf("report count = %d", reportCount)
	}
}
