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

	if _, err := pool.Exec(ctx, "TRUNCATE detector_signals, moderation_events"); err != nil {
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
		State: moderation.ProcessedAction,
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
	if state != string(moderation.ProcessedAction) {
		t.Errorf("terminal state = %q, want %q", state, moderation.ProcessedAction)
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
}
