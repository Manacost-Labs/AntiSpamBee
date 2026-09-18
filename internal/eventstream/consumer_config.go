package eventstream

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type consumerManager interface {
	CreateOrUpdateConsumer(context.Context, string, jetstream.ConsumerConfig) (jetstream.Consumer, error)
}

// EnsureModerationConsumer provisions the durable pull consumer used by the
// moderation worker. Unlimited delivery keeps database outages retryable.
func EnsureModerationConsumer(
	ctx context.Context,
	manager consumerManager,
	stream string,
	subject string,
	name string,
) (jetstream.Consumer, error) {
	if manager == nil {
		return nil, fmt.Errorf("consumer manager is required")
	}
	if stream == "" {
		return nil, fmt.Errorf("stream name is required")
	}
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}
	if name == "" {
		return nil, fmt.Errorf("consumer name is required")
	}

	consumer, err := manager.CreateOrUpdateConsumer(ctx, stream, jetstream.ConsumerConfig{
		Name:          name,
		Durable:       name,
		FilterSubject: subject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       30 * time.Second,
		MaxDeliver:    -1,
	})
	if err != nil {
		return nil, fmt.Errorf("ensure moderation consumer: %w", err)
	}
	return consumer, nil
}
