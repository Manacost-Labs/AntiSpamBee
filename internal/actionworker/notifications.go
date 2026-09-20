package actionworker

import (
	"antispambee/internal/telegramapi"
	"context"
	"errors"
	"time"
)

func (w *Worker) runNotificationOnce(ctx context.Context) (bool, error) {
	n, found, err := w.repository.ClaimNotification(ctx, w.owner, w.lease)
	if err != nil || !found {
		return false, err
	}
	finish := func(status, message string, next time.Time) (bool, error) {
		return true, w.repository.FinishNotification(ctx, n, status, next, message)
	}
	// Both durable binding and current Telegram membership are required. A
	// revoked administrator must not receive archived message contents.
	current, err := w.repository.NotificationRecipientCurrent(ctx, n)
	if err == nil && !current {
		return finish("CANCELLED", "recipient binding revoked", w.now())
	}
	if err == nil {
		var status string
		status, err = w.telegram.GetChatMemberStatus(ctx, n.CommunityChatID, n.Payload.ChatID)
		if err == nil && status != "administrator" && status != "creator" {
			return finish("CANCELLED", "recipient is no longer administrator", w.now())
		}
	}
	if err == nil {
		message := formatDeletionNotification(n.Payload)
		if message == "" {
			return finish("FAILED", "empty notification", w.now())
		}
		err = w.telegram.SendMessage(ctx, n.Payload.ChatID, message)
	}
	if err == nil {
		return finish("SENT", "", w.now())
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	if n.Attempts >= maxAttempts || !isRetryable(err) {
		return finish("FAILED", boundedError(err), w.now())
	}
	index := n.Attempts - 1
	if index < 0 {
		index = 0
	}
	delay := retryDelays[index]
	var apiErr *telegramapi.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		delay = apiErr.RetryAfter
	}
	return finish("RETRYABLE", boundedError(err), w.now().Add(delay))
}
