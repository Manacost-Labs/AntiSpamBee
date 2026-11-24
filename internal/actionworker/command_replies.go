package actionworker

import (
	"context"
	"errors"
	"strings"
	"time"

	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
)

func (w *Worker) runCommandReplyOnce(ctx context.Context) (bool, error) {
	reply, found, err := w.repository.ClaimCommandReply(ctx, w.owner, w.lease)
	if err != nil || !found {
		return false, err
	}
	finish := func(status, message string, next time.Time) (bool, error) {
		return true, w.repository.FinishCommandReply(ctx, reply, status, next, message)
	}
	if reply.Reply.ChatID == 0 || strings.TrimSpace(reply.Reply.Text) == "" {
		return finish("FAILED", "invalid command reply", w.now())
	}
	if reply.Reply.ReviewEventID == "" {
		err = w.telegram.SendMessage(ctx, reply.Reply.ChatID, reply.Reply.Text)
	} else {
		err = w.sendReview(ctx, reply)
		if errors.Is(err, errActionCancelled) {
			return finish("FAILED", "review expired or moderator changed", w.now())
		}
	}
	if err == nil {
		return finish("SENT", "", w.now())
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if reply.Attempts >= maxAttempts || !isRetryable(err) {
		return finish("FAILED", boundedError(err), w.now())
	}
	index := reply.Attempts - 1
	if index < 0 {
		index = 0
	}
	delay := retryDelays[index]
	var apiErr *telegramapi.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		delay = apiErr.RetryAfter
	}
	return finish("RETRYABLE", boundedError(err), w.now().UTC().Add(delay))
}

func (w *Worker) sendReview(ctx context.Context, reply moderation.ClaimedCommandReply) error {
	store, ok := w.repository.(interface {
		PendingReviewForModerator(context.Context, string, string, int64) (moderation.ReviewCase, bool, error)
	})
	telegram, supportsButtons := w.telegram.(interface {
		SendMessageWithCallbackButtons(context.Context, int64, string, []telegramapi.CallbackButton) error
	})
	if !ok || !supportsButtons {
		return errActionCancelled
	}
	chatID, reviewID := reply.Reply.ChatID, reply.Reply.ReviewEventID
	review, found, err := store.PendingReviewForModerator(ctx, reply.TenantID, reviewID, chatID)
	if err != nil {
		return err
	}
	if !found {
		return errActionCancelled
	}
	status, err := w.telegram.GetChatMemberStatus(ctx, review.Target.ChatID, chatID)
	if err != nil {
		return err
	}
	if status != "administrator" && status != "creator" {
		return errActionCancelled
	}
	return telegram.SendMessageWithCallbackButtons(ctx, chatID, reply.Reply.Text, []telegramapi.CallbackButton{
		{Text: "Оставить", Data: "review:keep:" + reviewID},
		{Text: "Удалить как спам", Data: "review:spam:" + reviewID},
	})
}
