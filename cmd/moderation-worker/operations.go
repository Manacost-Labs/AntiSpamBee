package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"antispambee/internal/postgresstore"
	"antispambee/internal/telegramapi"
	"github.com/nats-io/nats.go/jetstream"
)

type operationsAlert struct {
	kind string
	text string
}

func operationalAlerts(queueSlow, queueUnavailable bool, stats postgresstore.OperationsStatus, modelRetries uint64) []operationsAlert {
	var alerts []operationsAlert
	if queueUnavailable {
		alerts = append(alerts, operationsAlert{"queue_unavailable", "Потеряна связь с очередью модерации."})
	} else if queueSlow {
		alerts = append(alerts, operationsAlert{"queue_slow", "В очереди модерации накопилось 20 или больше событий. Проверьте задержку обработки."})
	}
	if stats.FailedActions > 0 || stats.RetryingActions >= 3 {
		alerts = append(alerts, operationsAlert{"telegram_actions", fmt.Sprintf("Telegram отклоняет действия модерации. Окончательных ошибок: %d, действий в повторной попытке: %d.", stats.FailedActions, stats.RetryingActions)})
	}
	if stats.ModelErrors >= 3 || modelRetries >= 3 {
		alerts = append(alerts, operationsAlert{"classification", "Модель распознавания неоднократно вернула ошибку. Часть сообщений может ждать повторной или ручной проверки."})
	}
	return alerts
}

func monitorOperations(ctx context.Context, chatID int64, consumer jetstream.Consumer, store *postgresstore.Store, telegram *telegramapi.Client, metrics *workerMetrics) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	next := make(map[string]time.Time)
	var slowSamples, unavailableSamples int
	var seenModelRetries uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		poll, cancel := context.WithTimeout(ctx, 12*time.Second)
		readQueue, cancelQueue := context.WithTimeout(poll, 2*time.Second)
		info, err := consumer.Info(readQueue)
		cancelQueue()
		if err != nil {
			unavailableSamples++
			slowSamples = 0
		} else {
			unavailableSamples = 0
			if info.NumPending+uint64(info.NumAckPending) >= 20 {
				slowSamples++
			} else {
				slowSamples = 0
			}
		}
		stats, err := store.OperationsStatus(poll, chatID)
		if err != nil {
			slog.Warn("moderation operation status unavailable")
			cancel()
			continue
		}
		modelRetries := metrics.modelRetries.Load()
		alerts := operationalAlerts(slowSamples >= 2, unavailableSamples >= 2, stats, modelRetries-seenModelRetries)
		if stats.ModeratorID == 0 || len(alerts) == 0 {
			cancel()
			continue
		}
		status, err := telegram.GetChatMemberStatus(poll, chatID, stats.ModeratorID)
		if err != nil || (status != "administrator" && status != "creator") {
			cancel()
			continue
		}
		for _, alert := range alerts {
			now := time.Now()
			if now.Before(next[alert.kind]) {
				continue
			}
			err := telegram.SendMessage(poll, stats.ModeratorID, "AntiSpamBee · "+alert.text)
			if err == nil {
				next[alert.kind] = now.Add(15 * time.Minute)
				if alert.kind == "classification" {
					seenModelRetries = modelRetries
				}
				continue
			}
			delay := time.Minute
			var apiErr *telegramapi.APIError
			if errors.As(err, &apiErr) && apiErr.RetryAfter > delay {
				delay = apiErr.RetryAfter
			}
			next[alert.kind] = now.Add(delay)
			slog.Warn("cannot deliver moderation operation alert", "kind", alert.kind)
		}
		cancel()
	}
}
