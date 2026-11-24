package postgresstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"antispambee/internal/events"
	"antispambee/internal/moderation"
	"github.com/jackc/pgx/v5"
)

func persistCommandCommit(ctx context.Context, tx pgx.Tx, event events.TelegramUpdate, outcome moderation.Outcome, firstDecision bool) error {
	if outcome.Decision.AuthorizationReason != moderation.ReasonModeratorCommand {
		return fmt.Errorf("command commit requires moderator command authorization")
	}
	var reason string
	if err := tx.QueryRow(ctx, `SELECT authorization_reason FROM moderation_decisions WHERE event_id=$1`, event.EventID).Scan(&reason); err != nil {
		return err
	}
	if reason != moderation.ReasonModeratorCommand {
		return fmt.Errorf("stored decision does not authorize a command")
	}
	inserted, err := tx.Exec(ctx, `INSERT INTO moderation_command_commits(event_id,tenant_id)
		VALUES($1,$2) ON CONFLICT(event_id) DO NOTHING`, event.EventID, event.TenantID)
	if err != nil {
		return fmt.Errorf("persist command completion: %w", err)
	}
	if inserted.RowsAffected() == 0 {
		return nil
	}
	// A legacy command decision already committed its effects before its reply.
	// Upgrade its delivery path without applying those effects a second time.
	if firstDecision {
		m := outcome.Command.Mutation
		if m.ProtectionLevel != "" {
			if m.ProtectionLevel != "OBSERVE" && m.ProtectionLevel != "SOFT" && m.ProtectionLevel != "STANDARD" && m.ProtectionLevel != "STRICT" {
				return fmt.Errorf("invalid command protection level")
			}
			if event.TenantID == "" || m.ChatID == 0 {
				return fmt.Errorf("invalid command policy target")
			}
			if err := setCommunityProtection(ctx, tx, event.TenantID, m.ChatID, m.ProtectionLevel); err != nil {
				return err
			}
		}
		if m.ModeratorUserID != 0 {
			if m.SenderChatID != 0 {
				if err := setCommunityModeratorSenderChat(ctx, tx, event.TenantID, m.ChatID, m.ModeratorUserID, m.SenderChatID); err != nil {
					return err
				}
			} else if err := setCommunityModerator(ctx, tx, event.TenantID, m.ChatID, m.ModeratorUserID); err != nil {
				return err
			}
		}
		if m.Allowlist != nil {
			a := m.Allowlist
			if m.ChatID == 0 || a.UserID <= 0 || a.AddedBy == 0 {
				return fmt.Errorf("invalid command allowlist target")
			}
			if err := setAllowlisted(ctx, tx, event.TenantID, m.ChatID, a.UserID, a.AddedBy, a.Allowed); err != nil {
				return err
			}
		}
	}
	for ordinal, reply := range outcome.Command.Replies {
		if reply.ChatID == 0 || strings.TrimSpace(reply.Text) == "" || len([]rune(reply.Text)) > 4096 {
			return fmt.Errorf("invalid command reply")
		}
		payload, err := json.Marshal(reply)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO moderation_command_reply_outbox(event_id,tenant_id,ordinal,payload)
			VALUES($1,$2,$3,$4)`, event.EventID, event.TenantID, ordinal, payload); err != nil {
			return fmt.Errorf("enqueue command reply: %w", err)
		}
	}
	return nil
}

func (s *Store) ClaimCommandReply(ctx context.Context, owner string, lease time.Duration) (moderation.ClaimedCommandReply, bool, error) {
	var reply moderation.ClaimedCommandReply
	if owner == "" || lease <= 0 {
		return reply, false, fmt.Errorf("invalid command reply lease")
	}
	var payload []byte
	err := s.pool.QueryRow(ctx, `WITH candidate AS (
		SELECT reply_id FROM moderation_command_reply_outbox
		WHERE expires_at>now() AND ((status IN ('PENDING','RETRYABLE') AND next_attempt_at<=now()) OR (status='CLAIMED' AND lease_until<=now()))
		ORDER BY next_attempt_at,created_at,ordinal FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE moderation_command_reply_outbox r SET status='CLAIMED',lease_owner=$1,lease_until=now()+($2 * interval '1 millisecond'),attempts=attempts+1,updated_at=now()
	FROM candidate WHERE r.reply_id=candidate.reply_id
	RETURNING r.reply_id::text,r.tenant_id::text,r.payload,r.attempts`, owner, lease.Milliseconds()).Scan(&reply.ReplyID, &reply.TenantID, &payload, &reply.Attempts)
	if errorsIsNoRows(err) {
		return reply, false, nil
	}
	if err != nil {
		return reply, false, fmt.Errorf("claim command reply: %w", err)
	}
	reply.LeaseOwner = owner
	if err := json.Unmarshal(payload, &reply.Reply); err != nil {
		return reply, false, fmt.Errorf("decode command reply: %w", err)
	}
	return reply, true, nil
}

func (s *Store) FinishCommandReply(ctx context.Context, reply moderation.ClaimedCommandReply, status string, next time.Time, message string) error {
	if status != "SENT" && status != "FAILED" && status != "RETRYABLE" {
		return fmt.Errorf("invalid command reply status")
	}
	result, err := s.pool.Exec(ctx, `UPDATE moderation_command_reply_outbox SET status=$4,next_attempt_at=$5,last_error=NULLIF($6,''),
		lease_owner=NULL,lease_until=NULL,updated_at=now(),payload=CASE WHEN $4='RETRYABLE' THEN payload ELSE '{}'::jsonb END
		WHERE reply_id=$1 AND lease_owner=$2 AND attempts=$3 AND status='CLAIMED'`, reply.ReplyID, reply.LeaseOwner, reply.Attempts, status, next, message)
	if err != nil {
		return fmt.Errorf("finish command reply: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("command reply lease no longer owned")
	}
	return nil
}
