package actionworker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
)

const (
	defaultLease = 30 * time.Second
	maxAttempts  = 5
)

var retryDelays = [...]time.Duration{
	1 * time.Second,
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// Repository owns action leasing and durable state transitions.
type Repository interface {
	ClaimAction(context.Context, string, time.Duration) (moderation.ClaimedAction, bool, error)
	MarkActionSucceeded(context.Context, moderation.ClaimedAction, bool) error
	MarkActionRetryable(context.Context, moderation.ClaimedAction, time.Time, string) error
	MarkActionPermanentFailure(context.Context, moderation.ClaimedAction, string) error
}

// TelegramClient is the least Telegram authority required by the worker.
type TelegramClient interface {
	BanChatMember(context.Context, int64, int64) error
	DeleteMessage(context.Context, int64, int64) error
	DeleteMessageReaction(context.Context, int64, int64, int64) error
	GetChatMemberStatus(context.Context, int64, int64) (string, error)
	RestrictChatMember(context.Context, int64, int64, int64) error
	UnbanChatMember(context.Context, int64, int64) error
}

// Worker leases and executes one durable moderation action at a time.
type Worker struct {
	repository Repository
	telegram   TelegramClient
	owner      string
	lease      time.Duration
	now        func() time.Time
}

func New(repository Repository, telegram TelegramClient, owner string) (*Worker, error) {
	if repository == nil {
		return nil, fmt.Errorf("action repository is required")
	}
	if telegram == nil {
		return nil, fmt.Errorf("Telegram client is required")
	}
	if owner == "" {
		return nil, fmt.Errorf("action worker owner is required")
	}
	return &Worker{
		repository: repository,
		telegram:   telegram,
		owner:      owner,
		lease:      defaultLease,
		now:        time.Now,
	}, nil
}

// RunOnce returns false when no due action was available.
func (w *Worker) RunOnce(ctx context.Context) (bool, error) {
	action, found, err := w.repository.ClaimAction(ctx, w.owner, w.lease)
	if err != nil || !found {
		return false, err
	}

	assumed, err := w.execute(ctx, action)
	if err == nil {
		if err := w.repository.MarkActionSucceeded(ctx, action, assumed); err != nil {
			return true, fmt.Errorf("mark moderation action succeeded: %w", err)
		}
		return true, nil
	}
	if ctx.Err() != nil {
		return true, ctx.Err()
	}

	message := boundedError(err)
	if action.AttemptCount >= maxAttempts || !isRetryable(err) {
		if err := w.repository.MarkActionPermanentFailure(ctx, action, message); err != nil {
			return true, fmt.Errorf("mark moderation action permanently failed: %w", err)
		}
		return true, nil
	}
	delay := retryDelays[action.AttemptCount-1]
	var apiErr *telegramapi.APIError
	if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
		delay = apiErr.RetryAfter
	}
	if err := w.repository.MarkActionRetryable(ctx, action, w.now().UTC().Add(delay), message); err != nil {
		return true, fmt.Errorf("mark moderation action retryable: %w", err)
	}
	return true, nil
}

func (w *Worker) execute(ctx context.Context, action moderation.ClaimedAction) (bool, error) {
	target := action.Target
	switch action.Type {
	case moderation.ActionDeleteMessage:
		return false, w.telegram.DeleteMessage(ctx, target.ChatID, target.MessageID)
	case moderation.ActionDeleteReaction:
		return false, w.telegram.DeleteMessageReaction(ctx, target.ChatID, target.MessageID, target.UserID)
	case moderation.ActionBanUser:
		if action.AttemptCount > 1 {
			status, err := w.telegram.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
			if err != nil {
				return false, fmt.Errorf("reconcile Telegram ban: %w", err)
			}
			if status == "kicked" {
				return true, nil
			}
		}
		return false, w.telegram.BanChatMember(ctx, target.ChatID, target.UserID)
	case moderation.ActionMuteUser:
		return false, w.telegram.RestrictChatMember(ctx, target.ChatID, target.UserID, action.UntilDate)
	case moderation.ActionUnbanUser:
		return false, w.telegram.UnbanChatMember(ctx, target.ChatID, target.UserID)
	default:
		return false, fmt.Errorf("unsupported moderation action %q", action.Type)
	}
}

func isRetryable(err error) bool {
	var apiErr *telegramapi.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	return apiErr.ErrorCode == 429 || apiErr.ErrorCode >= 500 || apiErr.ErrorCode == 0
}

func boundedError(err error) string {
	message := err.Error()
	if len(message) > 1000 {
		return message[:1000]
	}
	return message
}
