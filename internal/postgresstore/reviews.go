package postgresstore

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/moderation"
	"github.com/jackc/pgx/v5"
)

func enqueueReview(ctx context.Context, tx pgx.Tx, event events.TelegramUpdate, outcome moderation.Outcome) error {
	evidence := outcome.Evidence
	if !outcome.QueueReview || !outcome.Decision.NeedsModeratorReview() || evidence == nil || evidence.Target.Kind != moderation.TargetMessage ||
		evidence.Target.ChatID == 0 || evidence.Target.UserID <= 0 || evidence.Target.MessageID <= 0 || evidence.Protected {
		return nil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO moderation_reviews(event_id) VALUES ($1) ON CONFLICT DO NOTHING`, event.EventID); err != nil {
		return fmt.Errorf("record moderation review: %w", err)
	}
	if evidence.Policy.ModeratorChatID <= 0 {
		return nil
	}
	content := strings.TrimSpace(strings.Join([]string{evidence.Message.Text, evidence.Message.Caption, evidence.Message.OCRText}, "\n"))
	if content == "" {
		content = "Сообщение без текста. Откройте его в группе."
	}
	if runes := []rune(content); len(runes) > 900 {
		content = string(runes[:900]) + "…"
	}
	text := fmt.Sprintf("Сообщение на проверку\nГруппа %d, сообщение %d\n\n%s\n\nПричина: %s", evidence.Target.ChatID, evidence.Target.MessageID, content, reviewReason(outcome.Decision.AuthorizationReason))
	if strings.HasPrefix(fmt.Sprint(evidence.Target.ChatID), "-100") {
		text += fmt.Sprintf("\nhttps://t.me/c/%s/%d", strings.TrimPrefix(fmt.Sprint(evidence.Target.ChatID), "-100"), evidence.Target.MessageID)
	}
	for _, signal := range outcome.Signals {
		if signal.EvidenceExcerpt != "" {
			runes := []rune(signal.EvidenceExcerpt)
			text += "\nФрагмент: " + string(runes[:min(300, len(runes))])
			break
		}
	}
	payload, err := json.Marshal(moderation.CommandReply{ChatID: evidence.Policy.ModeratorChatID, Text: text, ReviewEventID: event.EventID})
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO moderation_command_reply_outbox(event_id,tenant_id,ordinal,payload)
		VALUES($1,$2,0,$3) ON CONFLICT (event_id,ordinal) DO NOTHING`, event.EventID, event.TenantID, payload); err != nil {
		return fmt.Errorf("queue review notification: %w", err)
	}
	return nil
}

func reviewReason(reason string) string {
	switch reason {
	case moderation.ReasonAdvertisingNotConfirmed:
		return "модели разошлись или подтверждение недоступно"
	case moderation.ReasonRepeatedCampaign:
		return "несколько авторов используют один рекламный контакт, ссылку или изображение"
	case moderation.ReasonMessageEvidenceRequired, moderation.ReasonInsufficientEvidence:
		return "не хватает подтверждения для автоматического удаления"
	case moderation.ReasonAutomaticActionsDisabled:
		return "для группы включена ручная модерация"
	default:
		return "бот не смог уверенно принять решение"
	}
}

func (s *Store) PendingReviewForModerator(ctx context.Context, tenant, eventID string, moderatorID int64) (moderation.ReviewCase, bool, error) {
	var review moderation.ReviewCase
	err := s.pool.QueryRow(ctx, `SELECT e.chat_id, e.message_id, (e.snapshot->'Target'->>'UserID')::bigint
		FROM moderation_reviews r JOIN moderation_evidence e USING(event_id)
		JOIN moderation_decisions d USING(event_id)
		JOIN community_policies p ON p.tenant_id=e.tenant_id AND p.chat_id=e.chat_id
		WHERE e.tenant_id=$1 AND e.event_id=$2 AND e.expires_at>now() AND r.verdict IS NULL AND p.moderator_chat_id=$3
		AND d.authorization_reason NOT IN ($4,$5)`, tenant, eventID, moderatorID,
		detection.ReasonOpenRouterFailed, moderation.ReasonMediaAnalysisUnavailable).Scan(&review.Target.ChatID, &review.Target.MessageID, &review.Target.UserID)
	if errorsIsNoRows(err) {
		return moderation.ReviewCase{}, false, nil
	}
	if err != nil {
		return moderation.ReviewCase{}, false, fmt.Errorf("read assigned review: %w", err)
	}
	review.Target.Kind = moderation.TargetMessage
	return review, true, nil
}

func (s *Store) ResolveReview(ctx context.Context, tenant, eventID string, moderatorID int64, spam bool) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	verdict := "KEEP"
	if spam {
		verdict = "SPAM"
	}
	var chatID, messageID, userID int64
	err = tx.QueryRow(ctx, `UPDATE moderation_reviews r SET verdict=$4,reviewer_id=$3,reviewed_at=now()
		FROM moderation_evidence e JOIN moderation_decisions d USING(event_id)
		JOIN community_policies p ON p.tenant_id=e.tenant_id AND p.chat_id=e.chat_id
		WHERE r.event_id=e.event_id AND e.event_id=$2 AND e.tenant_id=$1 AND e.expires_at>now()
		AND p.moderator_chat_id=$3 AND r.verdict IS NULL AND d.authorization_reason NOT IN ($5,$6)
		RETURNING e.chat_id,e.message_id,(e.snapshot->'Target'->>'UserID')::bigint`, tenant, eventID, moderatorID, verdict,
		detection.ReasonOpenRouterFailed, moderation.ReasonMediaAnalysisUnavailable).Scan(&chatID, &messageID, &userID)
	if errorsIsNoRows(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("resolve moderation review: %w", err)
	}
	if spam {
		if _, err := tx.Exec(ctx, `UPDATE moderation_events SET terminal_state='DECIDED_PENDING_ACTION',processed_at=now() WHERE event_id=$1`, eventID); err != nil {
			return false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO moderation_actions(decision_id,event_id,tenant_id,idempotency_key,action_type,chat_id,user_id,message_id,manual_review)
			SELECT d.decision_id,$1,$2,'review-delete:' || d.event_id::text,'DELETE_MESSAGE',$3,$4,$5,TRUE FROM moderation_decisions d WHERE d.event_id=$1`,
			eventID, tenant, chatID, userID, messageID); err != nil {
			return false, fmt.Errorf("queue review deletion: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}
