package postgresstore

import (
	"context"
	"fmt"

	"antispambee/internal/events"
	"antispambee/internal/moderation"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists terminal moderation outcomes in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a PostgreSQL-backed terminal event store.
func New(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, fmt.Errorf("PostgreSQL pool is required")
	}
	return &Store{pool: pool}, nil
}

// RecordTerminal inserts an outcome once. A retry of the same event succeeds
// without changing the original record; conflicting event identity is rejected.
func (s *Store) RecordTerminal(
	ctx context.Context,
	event events.TelegramUpdate,
	outcome moderation.Outcome,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin terminal moderation transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var eventID string
	err = tx.QueryRow(ctx, `
		INSERT INTO moderation_events (
			event_id,
			tenant_id,
			source_key,
			bot_id,
			telegram_update_id,
			schema_version,
			terminal_state
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (source_key) DO UPDATE
		SET source_key = EXCLUDED.source_key
		WHERE moderation_events.event_id = EXCLUDED.event_id
			AND moderation_events.tenant_id = EXCLUDED.tenant_id
			AND moderation_events.bot_id = EXCLUDED.bot_id
			AND moderation_events.telegram_update_id = EXCLUDED.telegram_update_id
			AND moderation_events.schema_version = EXCLUDED.schema_version
			AND moderation_events.terminal_state = EXCLUDED.terminal_state
		RETURNING event_id::text
	`,
		event.EventID,
		event.TenantID,
		event.SourceKey,
		event.BotID,
		event.UpdateID,
		event.SchemaVersion,
		outcome.State,
	).Scan(&eventID)
	if err != nil {
		return fmt.Errorf("insert terminal moderation event %q: %w", event.SourceKey, err)
	}

	if len(outcome.Signals) == 0 {
		return fmt.Errorf("insert terminal moderation event %q: no detector signals", event.SourceKey)
	}
	for _, signal := range outcome.Signals {
		_, err = tx.Exec(ctx, `
		INSERT INTO detector_signals (
			event_id,
			schema_version,
			detector,
			detector_version,
			category,
			status,
			score,
			confidence,
			severity,
			evidence_coverage,
			reason_codes,
			matched_rules,
			created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (event_id, detector, detector_version) DO NOTHING
		`,
			event.EventID,
			signal.SchemaVersion,
			signal.Detector,
			signal.DetectorVersion,
			signal.Category,
			signal.Status,
			signal.Score,
			signal.Confidence,
			signal.Severity,
			signal.EvidenceCoverage,
			signal.ReasonCodes,
			signal.MatchedRules,
			signal.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf(
				"insert detector signal %q for event %q: %w",
				signal.Detector,
				event.SourceKey,
				err,
			)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit terminal moderation event %q: %w", event.SourceKey, err)
	}
	return nil
}
