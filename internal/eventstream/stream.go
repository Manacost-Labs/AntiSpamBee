package eventstream

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

const telegramDuplicateWindow = 7 * 24 * time.Hour

type streamManager interface {
	CreateOrUpdateStream(context.Context, jetstream.StreamConfig) (jetstream.Stream, error)
}

// EnsureTelegramStream provisions the durable queue required before accepting webhooks.
func EnsureTelegramStream(ctx context.Context, manager streamManager, stream, subject string) error {
	if manager == nil {
		return fmt.Errorf("stream manager is required")
	}
	if stream == "" {
		return fmt.Errorf("stream name is required")
	}
	if subject == "" {
		return fmt.Errorf("subject is required")
	}

	_, err := manager.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       stream,
		Subjects:   []string{subject},
		Retention:  jetstream.WorkQueuePolicy,
		Storage:    jetstream.FileStorage,
		Replicas:   1,
		Duplicates: telegramDuplicateWindow,
	})
	if err != nil {
		return fmt.Errorf("ensure Telegram event stream: %w", err)
	}

	return nil
}
