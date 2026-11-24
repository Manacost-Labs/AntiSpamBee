package eventstream

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"antispambee/internal/events"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestSequentialConsumerDoesNotRedeliverBufferedEvents(t *testing.T) {
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
	name := fmt.Sprintf("PREFETCH_TEST_%d", time.Now().UnixNano())
	subject := "test." + name
	_, err = js.CreateStream(ctx, jetstream.StreamConfig{Name: name, Subjects: []string{subject}, Storage: jetstream.MemoryStorage})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := js.DeleteStream(context.Background(), name); err != nil {
			t.Error(err)
		}
	})
	consumer, err := js.CreateConsumer(ctx, name, jetstream.ConsumerConfig{Durable: "worker", AckPolicy: jetstream.AckExplicitPolicy, AckWait: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	event, _ := lifecycleEvent(t)
	for _, id := range []int64{789, 790} {
		identity, _ := events.NewTelegramIdentity(event.BotID, id)
		event.EventID, event.SourceKey, event.UpdateID = identity.EventID, identity.SourceKey, id
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(ctx, subject, data); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	processor := processorFunc(func(ctx context.Context, _ events.TelegramUpdate) error {
		if calls.Add(1) == 1 {
			// Leave the first callback busy for over three AckWait periods.
			timer := time.NewTimer(650 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})
	handler, _ := NewHandler(processor, time.Second)
	handler.progressInterval = 20 * time.Millisecond
	results := make(chan error, 4)
	consuming, err := consumer.Consume(func(msg jetstream.Msg) {
		metadata, err := msg.Metadata()
		if err == nil && metadata.NumDelivered != 1 {
			err = fmt.Errorf("message delivered %d times", metadata.NumDelivered)
		}
		if err == nil {
			err = handler.Handle(ctx, msg)
		}
		select {
		case results <- err:
		case <-ctx.Done():
		}
	}, jetstream.PullMaxMessages(ModerationPullBatchSize))
	if err != nil {
		t.Fatal(err)
	}
	defer consuming.Stop()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	info, err := consumer.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || info.NumAckPending != 0 || info.NumRedelivered != 0 || info.NumPending != 0 {
		t.Fatalf("calls=%d ack_pending=%d redelivered=%d pending=%d", calls.Load(), info.NumAckPending, info.NumRedelivered, info.NumPending)
	}
}
