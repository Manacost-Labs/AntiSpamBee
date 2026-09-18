package eventstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

type recordingStreamManager struct {
	config jetstream.StreamConfig
	err    error
}

func (m *recordingStreamManager) CreateOrUpdateStream(_ context.Context, config jetstream.StreamConfig) (jetstream.Stream, error) {
	m.config = config
	return nil, m.err
}

func TestEnsureTelegramStreamCreatesDurableWorkQueue(t *testing.T) {
	manager := &recordingStreamManager{}

	err := EnsureTelegramStream(context.Background(), manager, "TELEGRAM_EVENTS", "telegram.events")
	if err != nil {
		t.Fatalf("EnsureTelegramStream() error = %v", err)
	}

	config := manager.config
	if config.Name != "TELEGRAM_EVENTS" {
		t.Fatalf("stream name = %q", config.Name)
	}
	if len(config.Subjects) != 1 || config.Subjects[0] != "telegram.events" {
		t.Fatalf("subjects = %#v", config.Subjects)
	}
	if config.Storage != jetstream.FileStorage {
		t.Fatalf("storage = %v, want file storage", config.Storage)
	}
	if config.Retention != jetstream.WorkQueuePolicy {
		t.Fatalf("retention = %v, want work queue", config.Retention)
	}
	if config.Duplicates != 7*24*time.Hour {
		t.Fatalf("duplicate window = %s, want 7 days", config.Duplicates)
	}
}

func TestEnsureTelegramStreamReturnsProvisioningFailure(t *testing.T) {
	wantErr := errors.New("JetStream unavailable")
	manager := &recordingStreamManager{err: wantErr}

	err := EnsureTelegramStream(context.Background(), manager, "TELEGRAM_EVENTS", "telegram.events")
	if !errors.Is(err, wantErr) {
		t.Fatalf("EnsureTelegramStream() error = %v, want wrapped %v", err, wantErr)
	}
}
