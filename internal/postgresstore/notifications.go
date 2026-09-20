package postgresstore

import (
	"antispambee/internal/moderation"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Store) NotificationRecipientCurrent(ctx context.Context, n moderation.ClaimedNotification) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM community_policies WHERE tenant_id=$1 AND chat_id=$2 AND moderator_chat_id=$3)`, n.TenantID, n.CommunityChatID, n.Payload.ChatID).Scan(&allowed)
	return allowed, err
}

func (s *Store) ClaimNotification(ctx context.Context, owner string, lease time.Duration) (moderation.ClaimedNotification, bool, error) {
	var n moderation.ClaimedNotification
	if owner == "" || lease <= 0 {
		return n, false, fmt.Errorf("invalid notification lease")
	}
	var payload []byte
	err := s.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT action_id FROM moderation_notification_outbox
		WHERE expires_at > now() AND ((status IN ('PENDING','RETRYABLE') AND next_attempt_at <= now()) OR (status='CLAIMED' AND lease_until <= now()))
		ORDER BY next_attempt_at,action_id FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE moderation_notification_outbox n SET status='CLAIMED',lease_owner=$1,lease_until=now()+$2::interval,attempts=attempts+1,updated_at=now()
	FROM candidate WHERE n.action_id=candidate.action_id
	RETURNING n.action_id::text,n.tenant_id::text,n.community_chat_id,n.payload,n.attempts`, owner, lease.String()).Scan(&n.ActionID, &n.TenantID, &n.CommunityChatID, &payload, &n.Attempts)
	if errorsIsNoRows(err) {
		return n, false, nil
	}
	if err != nil {
		return n, false, fmt.Errorf("claim notification: %w", err)
	}
	n.LeaseOwner = owner
	if err := json.Unmarshal(payload, &n.Payload); err != nil {
		return n, false, fmt.Errorf("decode notification: %w", err)
	}
	return n, true, nil
}

func (s *Store) FinishNotification(ctx context.Context, n moderation.ClaimedNotification, status string, next time.Time, message string) error {
	if status != "SENT" && status != "FAILED" && status != "RETRYABLE" && status != "CANCELLED" {
		return fmt.Errorf("invalid notification status")
	}
	result, err := s.pool.Exec(ctx, `UPDATE moderation_notification_outbox SET status=$4,next_attempt_at=$5,last_error=NULLIF($6,''),
		lease_owner=NULL,lease_until=NULL,updated_at=now(),payload=CASE WHEN $4='RETRYABLE' THEN payload ELSE '{}'::jsonb END
		WHERE action_id=$1 AND lease_owner=$2 AND attempts=$3 AND status='CLAIMED'`, n.ActionID, n.LeaseOwner, n.Attempts, status, next, message)
	if err != nil {
		return fmt.Errorf("finish notification: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("notification lease no longer owned")
	}
	return nil
}

// PurgeExpiredEvidence deletes bounded batches; no full-table or unbounded work
// is performed on a delivery iteration. Live archive reads also check expiry.
func (s *Store) PurgeExpiredEvidence(ctx context.Context) error {
	for _, query := range []string{
		`DELETE FROM moderation_evidence WHERE event_id IN (SELECT event_id FROM moderation_evidence WHERE expires_at <= now() ORDER BY expires_at LIMIT 100)`,
		`DELETE FROM moderation_notification_outbox WHERE action_id IN (SELECT action_id FROM moderation_notification_outbox WHERE expires_at <= now() ORDER BY expires_at LIMIT 100)`,
	} {
		if _, err := s.pool.Exec(ctx, query); err != nil {
			return fmt.Errorf("expire moderation content: %w", err)
		}
	}
	return nil
}

func (s *Store) ListModerationHistory(ctx context.Context, tenantID string, chatID int64) ([]moderation.HistoryEntry, error) {
	if tenantID == "" || chatID == 0 {
		return nil, fmt.Errorf("tenant and chat required")
	}
	rows, err := s.pool.Query(ctx, `SELECT e.event_id::text,e.created_at,e.snapshot,
		COALESCE((SELECT string_agg(a.action_type || ': ' || a.status, ', ' ORDER BY a.action_type) FROM moderation_actions a WHERE a.event_id=e.event_id),'REVIEW')
		FROM moderation_evidence e WHERE e.tenant_id=$1 AND e.chat_id=$2 AND e.expires_at>now() ORDER BY e.created_at DESC,e.event_id LIMIT 5`, tenantID, chatID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	entries := []moderation.HistoryEntry{}
	for rows.Next() {
		var entry moderation.HistoryEntry
		var payload []byte
		if err := rows.Scan(&entry.EventID, &entry.CreatedAt, &payload, &entry.Actions); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(payload, &entry.Evidence); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
