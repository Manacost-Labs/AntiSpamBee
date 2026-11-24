package postgresstore

import (
	"context"
	"time"
)

type OperationsStatus struct {
	ModeratorID     int64
	FailedActions   int
	RetryingActions int
	ModelErrors     int
}

func (s *Store) OperationsStatus(ctx context.Context, chatID int64) (OperationsStatus, error) {
	var status OperationsStatus
	err := s.pool.QueryRow(ctx, `SELECT
		COALESCE((SELECT moderator_chat_id FROM community_policies WHERE chat_id=$1 AND moderator_chat_id>0 ORDER BY updated_at DESC LIMIT 1),0),
		(SELECT count(*) FROM moderation_actions WHERE chat_id=$1 AND status='PERMANENT_FAILED' AND updated_at >= now()-interval '5 minutes'),
		(SELECT count(*) FROM moderation_actions WHERE chat_id=$1 AND status='RETRYABLE' AND updated_at >= now()-interval '5 minutes'),
		(SELECT count(*) FROM detector_signals s WHERE s.detector='model.message_advertising'
			AND s.status='ERROR' AND s.created_at>=now()-interval '5 minutes'
			AND (EXISTS (SELECT 1 FROM moderation_evidence e WHERE e.event_id=s.event_id AND e.chat_id=$1)
			  OR EXISTS (SELECT 1 FROM message_activity a WHERE a.event_id=s.event_id AND a.chat_id=$1)))`, chatID).
		Scan(&status.ModeratorID, &status.FailedActions, &status.RetryingActions, &status.ModelErrors)
	return status, err
}

func (s *Store) ReserveOperationsAlert(ctx context.Context, chatID int64, kind string, cooldown time.Duration) (time.Time, error) {
	var reservedUntil time.Time
	err := s.pool.QueryRow(ctx, `INSERT INTO moderation_operation_alerts (chat_id, kind, next_available_at)
		VALUES ($1, $2, now()+$3*interval '1 second')
		ON CONFLICT (chat_id, kind) DO UPDATE SET next_available_at=EXCLUDED.next_available_at
		WHERE moderation_operation_alerts.next_available_at<=now()
		RETURNING next_available_at`, chatID, kind, cooldown.Seconds()).Scan(&reservedUntil)
	if errorsIsNoRows(err) {
		return time.Time{}, nil
	}
	return reservedUntil, err
}

func (s *Store) RescheduleOperationsAlert(ctx context.Context, chatID int64, kind string, reservedUntil time.Time, delay time.Duration) error {
	_, err := s.pool.Exec(ctx, `UPDATE moderation_operation_alerts SET next_available_at=now()+$4*interval '1 second'
		WHERE chat_id=$1 AND kind=$2 AND next_available_at=$3`, chatID, kind, reservedUntil, delay.Seconds())
	return err
}
