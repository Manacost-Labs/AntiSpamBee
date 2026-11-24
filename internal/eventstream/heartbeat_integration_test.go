package eventstream

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"antispambee/internal/events"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestHandlerHeartbeatPreventsBrokerRedelivery(t *testing.T) {
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL is not set")
	}
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	name := fmt.Sprintf("HEARTBEAT_TEST_%d", time.Now().UnixNano())
	subject := "test." + name
	if _, err := js.CreateStream(ctx, jetstream.StreamConfig{Name: name, Subjects: []string{subject}, Storage: jetstream.MemoryStorage}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := js.DeleteStream(context.Background(), name); err != nil {
			t.Errorf("cleanup test stream: %v", err)
		}
	})
	consumer, err := js.CreateConsumer(ctx, name, jetstream.ConsumerConfig{Durable: "worker", AckPolicy: jetstream.AckExplicitPolicy, AckWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	_, data := lifecycleEvent(t)
	if _, err := js.Publish(ctx, subject, data); err != nil {
		t.Fatal(err)
	}
	message, err := consumer.Next(jetstream.FetchMaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	processor := processorFunc(func(ctx context.Context, _ events.TelegramUpdate) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	handler, _ := NewHandler(processor, time.Second)
	handler.progressInterval = 20 * time.Millisecond
	result := make(chan error, 1)
	go func() { result <- handler.Handle(ctx, message) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// A second pull spans multiple AckWait periods. It would receive a duplicate
	// without the handler's progress acknowledgments.
	if duplicate, err := consumer.Next(jetstream.FetchMaxWait(650 * time.Millisecond)); duplicate != nil || !errors.Is(err, nats.ErrTimeout) {
		t.Fatalf("unexpected redelivery while processing: message=%v error=%v", duplicate, err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	info, err := consumer.Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if info.NumRedelivered != 0 || info.NumAckPending != 0 {
		t.Fatalf("broker redeliveries=%d unacknowledged=%d", info.NumRedelivered, info.NumAckPending)
	}
}
