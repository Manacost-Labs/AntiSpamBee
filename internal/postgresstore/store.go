package postgresstore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"antispambee/internal/events"
	"antispambee/internal/moderation"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store persists terminal moderation outcomes in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// ClaimAction leases the oldest due action. Expired leases are recoverable.
func (s *Store) ClaimAction(
	ctx context.Context,
	owner string,
	lease time.Duration,
) (moderation.ClaimedAction, bool, error) {
	if owner == "" || lease <= 0 {
		return moderation.ClaimedAction{}, false, fmt.Errorf("valid action lease owner and duration are required")
	}
	var action moderation.ClaimedAction
	var actionType moderation.ActionType
	err := s.pool.QueryRow(ctx, `
		WITH candidate AS (
			SELECT action_id
			FROM moderation_actions
			WHERE (
				status IN ('PENDING', 'RETRYABLE')
				AND next_attempt_at <= now()
			) OR (
				status = 'CLAIMED'
				AND lease_until < now()
			)
			ORDER BY next_attempt_at, created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE moderation_actions AS action
		SET status = 'CLAIMED',
			lease_owner = $1,
			lease_until = now() + ($2 * interval '1 millisecond'),
			attempt_count = action.attempt_count + 1,
			updated_at = now()
		FROM candidate
		WHERE action.action_id = candidate.action_id
		RETURNING
			action.action_id::text,
			action.event_id::text,
			action.tenant_id::text,
			action.lease_owner,
			action.action_type,
			action.chat_id,
			action.user_id,
			action.message_id,
			action.attempt_count
	`, owner, lease.Milliseconds()).Scan(
		&action.ActionID,
		&action.EventID,
		&action.TenantID,
		&action.LeaseOwner,
		&actionType,
		&action.Target.ChatID,
		&action.Target.UserID,
		&action.Target.MessageID,
		&action.AttemptCount,
	)
	if errorsIsNoRows(err) {
		return moderation.ClaimedAction{}, false, nil
	}
	if err != nil {
		return moderation.ClaimedAction{}, false, fmt.Errorf("claim moderation action: %w", err)
	}
	action.Type = actionType
	switch action.Type {
	case moderation.ActionDeleteMessage:
		action.Target.Kind = moderation.TargetMessage
	case moderation.ActionDeleteReaction:
		action.Target.Kind = moderation.TargetReaction
	case moderation.ActionBanUser:
		action.Target.Kind = moderation.TargetMessage
	}
	return action, true, nil
}

// MarkActionSucceeded atomically completes an action, its event, and audit row.
func (s *Store) MarkActionSucceeded(
	ctx context.Context,
	action moderation.ClaimedAction,
	assumed bool,
) error {
	status := "SUCCEEDED"
	operation := "ACTION_SUCCEEDED"
	if assumed {
		status = "SUCCEEDED_ASSUMED"
		operation = "ACTION_SUCCEEDED_ASSUMED"
	}
	return s.finishAction(ctx, action, status, moderation.ProcessedAction, operation, "")
}

// MarkActionRetryable releases a lease and schedules another attempt.
func (s *Store) MarkActionRetryable(
	ctx context.Context,
	action moderation.ClaimedAction,
	next time.Time,
	message string,
) error {
	command, err := s.pool.Exec(ctx, `
		UPDATE moderation_actions
		SET status = 'RETRYABLE', next_attempt_at = $3, last_error = $4,
			lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE action_id = $1 AND status = 'CLAIMED' AND lease_owner = $2
	`, action.ActionID, action.LeaseOwner, next, message)
	if err != nil {
		return fmt.Errorf("mark moderation action retryable: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("mark moderation action retryable: lease no longer owned")
	}
	return nil
}

// MarkActionPermanentFailure moves the action and event to dead letter.
func (s *Store) MarkActionPermanentFailure(
	ctx context.Context,
	action moderation.ClaimedAction,
	message string,
) error {
	return s.finishAction(ctx, action, "PERMANENT_FAILED", moderation.TerminalState("DEAD_LETTER"), "ACTION_FAILED", message)
}

func (s *Store) finishAction(
	ctx context.Context,
	action moderation.ClaimedAction,
	actionStatus string,
	eventStatus moderation.TerminalState,
	operation string,
	message string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin moderation action completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	command, err := tx.Exec(ctx, `
		UPDATE moderation_actions
		SET status = $3, last_error = NULLIF($4, ''), lease_owner = NULL,
			lease_until = NULL, updated_at = now()
		WHERE action_id = $1 AND status = 'CLAIMED' AND lease_owner = $2
	`, action.ActionID, action.LeaseOwner, actionStatus, message)
	if err != nil {
		return fmt.Errorf("complete moderation action: %w", err)
	}
	if command.RowsAffected() != 1 {
		return fmt.Errorf("complete moderation action: lease no longer owned")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE moderation_events SET terminal_state = $2, processed_at = now()
		WHERE event_id = $1
	`, action.EventID, eventStatus); err != nil {
		return fmt.Errorf("complete moderation event: %w", err)
	}
	details, err := json.Marshal(map[string]any{
		"action_type": action.Type,
		"status":      actionStatus,
		"error":       message,
	})
	if err != nil {
		return fmt.Errorf("encode action audit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO moderation_audit_log (
			tenant_id, event_id, action_id, actor_type, actor_id, operation, details
		)
		VALUES ($1, $2, $3, 'SYSTEM', 'action-worker-v1', $4, $5)
		ON CONFLICT (event_id, actor_type, actor_id, operation) DO NOTHING
	`, action.TenantID, action.EventID, action.ActionID, operation, details); err != nil {
		return fmt.Errorf("insert action audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit moderation action completion: %w", err)
	}
	return nil
}

func errorsIsNoRows(err error) bool { return err == pgx.ErrNoRows }

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
	if outcome.Decision.AuthorizedAction == "" {
		return fmt.Errorf("record moderation decision %q: authorized action is required", event.SourceKey)
	}
	if outcome.State == moderation.DecidedPendingAction && outcome.Action == nil {
		return fmt.Errorf("record moderation decision %q: pending state requires an action", event.SourceKey)
	}
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

	var decisionID string
	err = tx.QueryRow(ctx, `
		INSERT INTO moderation_decisions (
			decision_id,
			event_id,
			risk_score,
			decision_confidence,
			evidence_coverage,
			recommended_action,
			authorized_action,
			authorization_reason
		)
		VALUES ($1, $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (event_id) DO UPDATE
		SET event_id = EXCLUDED.event_id
		WHERE moderation_decisions.risk_score = EXCLUDED.risk_score
			AND moderation_decisions.decision_confidence = EXCLUDED.decision_confidence
			AND moderation_decisions.evidence_coverage = EXCLUDED.evidence_coverage
			AND moderation_decisions.recommended_action = EXCLUDED.recommended_action
			AND moderation_decisions.authorized_action = EXCLUDED.authorized_action
			AND moderation_decisions.authorization_reason = EXCLUDED.authorization_reason
		RETURNING decision_id::text
	`,
		event.EventID,
		outcome.Decision.RiskScore,
		outcome.Decision.DecisionConfidence,
		outcome.Decision.EvidenceCoverage,
		outcome.Decision.RecommendedAction,
		outcome.Decision.AuthorizedAction,
		outcome.Decision.AuthorizationReason,
	).Scan(&decisionID)
	if err != nil {
		return fmt.Errorf("insert moderation decision for event %q: %w", event.SourceKey, err)
	}

	if outcome.Action != nil {
		if outcome.Action.IdempotencyKey == "" {
			return fmt.Errorf("insert moderation action for event %q: idempotency key is required", event.SourceKey)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO moderation_actions (
				decision_id,
				event_id,
				tenant_id,
				idempotency_key,
				action_type,
				chat_id,
				user_id,
				message_id
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (idempotency_key) DO NOTHING
		`,
			decisionID,
			event.EventID,
			event.TenantID,
			outcome.Action.IdempotencyKey,
			outcome.Action.Type,
			outcome.Action.Target.ChatID,
			outcome.Action.Target.UserID,
			outcome.Action.Target.MessageID,
		)
		if err != nil {
			return fmt.Errorf("insert moderation action for event %q: %w", event.SourceKey, err)
		}
	}

	auditDetails, err := json.Marshal(map[string]any{
		"risk_score":           outcome.Decision.RiskScore,
		"recommended_action":   outcome.Decision.RecommendedAction,
		"authorized_action":    outcome.Decision.AuthorizedAction,
		"authorization_reason": outcome.Decision.AuthorizationReason,
	})
	if err != nil {
		return fmt.Errorf("encode moderation audit for event %q: %w", event.SourceKey, err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO moderation_audit_log (
			tenant_id, event_id, actor_type, actor_id, operation, details
		)
		VALUES ($1, $2, 'SYSTEM', 'decision-engine-v1', 'DECISION_RECORDED', $3)
		ON CONFLICT (event_id, actor_type, actor_id, operation) DO NOTHING
	`, event.TenantID, event.EventID, auditDetails)
	if err != nil {
		return fmt.Errorf("insert moderation audit for event %q: %w", event.SourceKey, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit terminal moderation event %q: %w", event.SourceKey, err)
	}
	return nil
}
