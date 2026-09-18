package eventstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type recordingConsumerManager struct {
	stream string
	config jetstream.ConsumerConfig
	err    error
}

func (m *recordingConsumerManager) CreateOrUpdateConsumer(
	_ context.Context,
	stream string,
	config jetstream.ConsumerConfig,
) (jetstream.Consumer, error) {
	m.stream = stream
	m.config = config
	return nil, m.err
}

func TestEnsureModerationConsumerCreatesDurablePullConsumer(t *testing.T) {
	manager := &recordingConsumerManager{}

	_, err := EnsureModerationConsumer(
		context.Background(),
		manager,
		"TELEGRAM_EVENTS",
		"telegram.events",
		"moderation-worker",
	)
	if err != nil {
		t.Fatalf("EnsureModerationConsumer() error = %v", err)
	}

	if manager.stream != "TELEGRAM_EVENTS" {
		t.Errorf("stream = %q", manager.stream)
	}
	config := manager.config
	if config.Name != "moderation-worker" || config.Durable != "moderation-worker" {
		t.Errorf("consumer name = %q, durable = %q", config.Name, config.Durable)
	}
	if config.FilterSubject != "telegram.events" {
		t.Errorf("filter subject = %q", config.FilterSubject)
	}
	if config.AckPolicy != jetstream.AckExplicitPolicy {
		t.Errorf("ack policy = %v", config.AckPolicy)
	}
	if config.AckWait != 30*time.Second {
		t.Errorf("ack wait = %s", config.AckWait)
	}
	if config.MaxDeliver != -1 {
		t.Errorf("max deliver = %d, want unlimited", config.MaxDeliver)
	}
}

func TestEnsureModerationConsumerReturnsProvisioningFailure(t *testing.T) {
	wantErr := errors.New("JetStream unavailable")
	manager := &recordingConsumerManager{err: wantErr}

	_, err := EnsureModerationConsumer(
		context.Background(),
		manager,
		"TELEGRAM_EVENTS",
		"telegram.events",
		"moderation-worker",
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("EnsureModerationConsumer() error = %v, want wrapped %v", err, wantErr)
	}
}
