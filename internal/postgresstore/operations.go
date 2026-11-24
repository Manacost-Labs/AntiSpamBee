package postgresstore

import "context"

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
