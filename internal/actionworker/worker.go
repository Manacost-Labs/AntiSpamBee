package actionworker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

var errActionCancelled = errors.New("action cancelled by moderation policy")

// Repository owns action leasing and durable state transitions.
type Repository interface {
	GetCommunityPolicy(context.Context, string, int64, int64) (moderation.CommunityPolicy, error)
	ClaimAction(context.Context, string, time.Duration) (moderation.ClaimedAction, bool, error)
	MarkActionSucceeded(context.Context, moderation.ClaimedAction, bool) error
	MarkActionRetryable(context.Context, moderation.ClaimedAction, time.Time, string) error
	MarkActionPermanentFailure(context.Context, moderation.ClaimedAction, string) error
	MarkActionCancelled(context.Context, moderation.ClaimedAction, string) error
	ClaimNotification(context.Context, string, time.Duration) (moderation.ClaimedNotification, bool, error)
	FinishNotification(context.Context, moderation.ClaimedNotification, string, time.Time, string) error
	ClaimCommandReply(context.Context, string, time.Duration) (moderation.ClaimedCommandReply, bool, error)
	FinishCommandReply(context.Context, moderation.ClaimedCommandReply, string, time.Time, string) error
	NotificationRecipientCurrent(context.Context, moderation.ClaimedNotification) (bool, error)
	PurgeExpiredEvidence(context.Context) error
}

// TelegramClient is the least Telegram authority required by the worker.
type TelegramClient interface {
	BanChatMember(context.Context, int64, int64) error
	DeleteMessage(context.Context, int64, int64) error
	DeleteMessageReaction(context.Context, int64, int64, int64) error
	GetChatMemberStatus(context.Context, int64, int64) (string, error)
	RestrictChatMember(context.Context, int64, int64, int64) error
	UnbanChatMember(context.Context, int64, int64) error
	SendMessage(context.Context, int64, string) error
}

// Worker leases and executes one durable moderation action at a time.
type Worker struct {
	repository Repository
	telegram   TelegramClient
	owner      string
	lease      time.Duration
	now        func() time.Time
	nextPurge  time.Time
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
	if !w.now().Before(w.nextPurge) {
		if err := w.repository.PurgeExpiredEvidence(ctx); err != nil {
			return false, err
		}
		w.nextPurge = w.now().Add(time.Minute)
	}
	worked, actionErr := w.runActionOnce(ctx)
	notified, notificationErr := w.runNotificationOnce(ctx)
	replied, replyErr := w.runCommandReplyOnce(ctx)
	return worked || notified || replied, errors.Join(actionErr, notificationErr, replyErr)
}

func (w *Worker) runActionOnce(ctx context.Context) (bool, error) {
	action, found, err := w.repository.ClaimAction(ctx, w.owner, w.lease)
	if err != nil || !found {
		return false, err
	}

	assumed, err := w.execute(ctx, action)
	if errors.Is(err, errActionCancelled) {
		return true, w.repository.MarkActionCancelled(ctx, action, boundedError(err))
	}
	if err == nil {
		if err := w.repository.MarkActionSucceeded(ctx, action, assumed); err != nil {
			return true, fmt.Errorf("mark moderation action succeeded: %w", err)
		}
		if action.Type == moderation.ActionBanUser && action.AuthorizationReason != moderation.ReasonConfirmedAdvertisingAutoban {
			message := fmt.Sprintf("⛔ Пользователь %d заблокирован модерацией AntiSpamBee.", action.Target.UserID)
			if err := w.telegram.SendMessage(ctx, action.Target.ChatID, message); err != nil {
				slog.Warn("send Telegram ban notification failed", "action_id", action.ActionID, "error", err)
			}
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

func formatDeletionNotification(notification moderation.DeletionNotification) string {
	message := strings.TrimSpace(notification.Message)
	if notification.ChatID == 0 || message == "" {
		return ""
	}
	author := fmt.Sprintf("ID %d", notification.AuthorUserID)
	if username := strings.TrimPrefix(strings.TrimSpace(notification.AuthorUsername), "@"); username != "" {
		author = "@" + username
	}
	reasons := make([]string, 0, len(notification.Reasons))
	for _, reason := range notification.Reasons {
		reasons = append(reasons, deletionReasonLabel(reason))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "подозрительная реклама или спам")
	}
	return fmt.Sprintf(
		"🗑 Удалено сообщение\nАвтор: %s\nПричина: %s\nРиск: %.2f\n\nТекст:\n%s",
		author,
		strings.Join(reasons, ", "),
		notification.RiskScore,
		truncateRunes(message, 3000),
	)
}

func deletionReasonLabel(reason string) string {
	switch reason {
	case "COMMERCIAL_PROMOTION":
		return "коммерческая реклама"
	case "VPN_PROMOTION":
		return "реклама VPN"
	case "GAMBLING_PROMOTION":
		return "реклама азартных игр"
	case "CRYPTO_INVESTMENT_PROMOTION":
		return "крипто-инвестиционная реклама"
	case "LOAN_PROMOTION":
		return "реклама займов"
	case "MASS_JOB_OFFER":
		return "массовая вакансия"
	case "ADULT_CONTENT":
		return "контент 18+"
	case moderation.ReasonConfirmedAdultChannel:
		return "порнографический или эротический канал в профиле"
	case moderation.ReasonConfirmedFraudChannel:
		return "мошенническое предложение в канале профиля"
	case moderation.ReasonConfirmedProfileAdvertising:
		return "подтверждённая реклама в профиле"
	case "SERVICE_OFFER":
		return "реклама услуг"
	case "ACCOUNT_TRADE":
		return "торговля аккаунтами или идентификаторами"
	case "SUBSCRIPTION_SALE":
		return "продажа подписок"
	case "INFORMAL_JOB_OFFER":
		return "реклама работы"
	case "OPAQUE_TRADE_OFFER":
		return "торговое предложение с ценой и специальным жаргоном"
	case "DUPLICATE_SPAM":
		return "повторяющийся спам"
	case "MESSAGE_FLOOD":
		return "флуд"
	case "PRIOR_MODERATION_VIOLATIONS":
		return "повторные нарушения"
	default:
		return reason
	}
}

func truncateRunes(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func (w *Worker) execute(ctx context.Context, action moderation.ClaimedAction) (bool, error) {
	target := action.Target
	switch action.Type {
	case moderation.ActionDeleteMessage:
		// Cancel actions queued by the retired profile-only policy as well.
		if action.AuthorizationReason == moderation.ReasonProfileChannelAdvertising {
			return false, fmt.Errorf("%w: profile-only deletion is disabled", errActionCancelled)
		}
		// Older actions may contain Telegram's compatibility senders instead of
		// the real author of a chat/channel message. Their rights cannot be checked.
		if target.UserID <= 0 || target.UserID == 777000 || target.UserID == 1087968824 {
			return false, fmt.Errorf("%w: message author identity is unavailable", errActionCancelled)
		}
		if target.UserID > 0 {
			status, err := w.telegram.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
			if err != nil {
				return false, fmt.Errorf("check message author before deletion: %w", err)
			}
			if status == "administrator" || status == "creator" {
				return false, fmt.Errorf("%w: message author is an administrator", errActionCancelled)
			}
		}
		if err := w.checkCurrentPolicy(ctx, action); err != nil {
			return false, err
		}
		err := w.telegram.DeleteMessage(ctx, target.ChatID, target.MessageID)
		var apiErr *telegramapi.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode == 400 && strings.Contains(strings.ToLower(apiErr.Description), "message to delete not found") {
			return true, nil
		}
		return false, err
	case moderation.ActionDeleteReaction:
		if err := w.checkCurrentPolicy(ctx, action); err != nil {
			return false, err
		}
		return false, w.telegram.DeleteMessageReaction(ctx, target.ChatID, target.MessageID, target.UserID)
	case moderation.ActionBanUser:
		if target.UserID <= 0 || target.UserID == 777000 || target.UserID == 1087968824 {
			return false, fmt.Errorf("%w: ban target identity is unavailable", errActionCancelled)
		}
		status, err := w.telegram.GetChatMemberStatus(ctx, target.ChatID, target.UserID)
		if err != nil {
			return false, fmt.Errorf("check member before Telegram ban: %w", err)
		}
		if status == "administrator" || status == "creator" {
			return false, fmt.Errorf("%w: ban target is an administrator", errActionCancelled)
		}
		if err := w.checkCurrentPolicy(ctx, action); err != nil {
			return false, err
		}
		if status == "kicked" {
			return true, nil
		}
		return false, w.telegram.BanChatMember(ctx, target.ChatID, target.UserID)
	case moderation.ActionMuteUser:
		if err := w.checkCurrentPolicy(ctx, action); err != nil {
			return false, err
		}
		return false, w.telegram.RestrictChatMember(ctx, target.ChatID, target.UserID, action.UntilDate)
	case moderation.ActionUnbanUser:
		if err := w.checkCurrentPolicy(ctx, action); err != nil {
			return false, err
		}
		return false, w.telegram.UnbanChatMember(ctx, target.ChatID, target.UserID)
	default:
		return false, fmt.Errorf("unsupported moderation action %q", action.Type)
	}
}

// Manual commands carry their own authorization. Automatic actions must still
// be permitted by the community at execution time, including on every retry.
func (w *Worker) checkCurrentPolicy(ctx context.Context, action moderation.ClaimedAction) error {
	if action.AuthorizationReason == moderation.ReasonModeratorCommand {
		return nil
	}
	policy, err := w.repository.GetCommunityPolicy(ctx, action.TenantID, action.Target.ChatID, action.Target.UserID)
	if err != nil {
		return fmt.Errorf("read current policy before automatic action: %w", err)
	}
	if policy.IsAllowlisted {
		return fmt.Errorf("%w: target is now allowlisted", errActionCancelled)
	}
	if !policy.AutomaticActionsEnabled || policy.ProtectionLevel == "OBSERVE" {
		return fmt.Errorf("%w: automatic actions are now disabled", errActionCancelled)
	}
	if policy.ProtectionLevel != "STRICT" && policy.ProtectionLevel != "STANDARD" {
		return fmt.Errorf("%w: unsupported protection level", errActionCancelled)
	}
	if action.Type == moderation.ActionBanUser && !policy.AutobanEnabled {
		return fmt.Errorf("%w: automatic bans are now disabled", errActionCancelled)
	}
	profileAction := action.Type == moderation.ActionBanUser
	switch action.AuthorizationReason {
	case moderation.ReasonConfirmedAdvertisingChannel, moderation.ReasonConfirmedAdultAdvertisingChannel, moderation.ReasonConfirmedProfileAdvertising,
		moderation.ReasonConfirmedAdvertisingAutoban,
		moderation.ReasonConfirmedAdultChannel, moderation.ReasonConfirmedFraudChannel, moderation.ReasonAutobanDisabled:
		profileAction = true
	}
	if profileAction && policy.ProtectionLevel != "STRICT" {
		return fmt.Errorf("%w: profile enforcement now requires STRICT protection", errActionCancelled)
	}
	return nil
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
