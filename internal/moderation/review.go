package moderation

import (
	"context"
	"encoding/json"
	"regexp"

	"antispambee/internal/events"
)

type ReviewCase struct {
	Target ActionTarget
}

type reviewStore interface {
	PendingReviewForModerator(context.Context, string, string, int64) (ReviewCase, bool, error)
	ResolveReview(context.Context, string, string, int64, bool) (bool, error)
}

type callbackTelegram interface {
	AnswerCallbackQuery(context.Context, string, string) error
}

var reviewCallbackPattern = regexp.MustCompile(`^review:(keep|spam):([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)

type reviewCallback struct {
	ID      string             `json:"id"`
	Data    string             `json:"data"`
	From    struct{ ID int64 } `json:"from"`
	Message struct {
		Chat struct {
			ID   int64  `json:"id"`
			Type string `json:"type"`
		} `json:"chat"`
	} `json:"message"`
}

func (r *CommandRouter) processReviewCallback(ctx context.Context, event events.TelegramUpdate) (bool, error) {
	var update struct {
		Callback *reviewCallback `json:"callback_query"`
	}
	if json.Unmarshal(event.Payload, &update) != nil || update.Callback == nil {
		return false, nil
	}
	callback := update.Callback
	match := reviewCallbackPattern.FindStringSubmatch(callback.Data)
	if match == nil || callback.ID == "" {
		return false, nil
	}
	answer := "Решение уже принято или карточка недоступна."
	store, supported := r.store.(reviewStore)
	if supported && callback.From.ID > 0 && callback.Message.Chat.Type == "private" && callback.Message.Chat.ID == callback.From.ID {
		id, moderatorID := match[2], callback.From.ID
		review, found, err := store.PendingReviewForModerator(ctx, event.TenantID, id, moderatorID)
		if err != nil {
			return true, err
		}
		if found {
			status, err := r.telegram.GetChatMemberStatus(ctx, review.Target.ChatID, moderatorID)
			if err != nil {
				return true, err
			}
			if status == "administrator" || status == "creator" {
				spam := match[1] == "spam"
				accepted, err := store.ResolveReview(ctx, event.TenantID, id, moderatorID, spam)
				if err != nil {
					return true, err
				}
				if accepted {
					answer = "Отмечено. Сообщение оставлено."
					if spam {
						answer = "Отмечено как спам. Удаление в очереди."
					}
				}
			}
		}
	}
	if err := r.recordCommand(ctx, event, nil, CommandCommit{}); err != nil {
		return true, err
	}
	if telegram, ok := r.telegram.(callbackTelegram); ok {
		_ = telegram.AnswerCallbackQuery(ctx, callback.ID, answer)
	}
	return true, nil
}
