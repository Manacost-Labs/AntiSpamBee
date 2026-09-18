package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"antispambee/internal/events"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type recordingJetStream struct {
	message *nats.Msg
	err     error
}

func (j *recordingJetStream) PublishMsg(_ context.Context, message *nats.Msg, _ ...jetstream.PublishOpt) (*jetstream.PubAck, error) {
	j.message = message
	if j.err != nil {
		return nil, j.err
	}
	return &jetstream.PubAck{Stream: "TELEGRAM_EVENTS", Sequence: 1}, nil
}

func TestPublisherPersistsVersionedEventWithDeduplicationKey(t *testing.T) {
	js := &recordingJetStream{}
	publisher, err := NewPublisher(js, "TELEGRAM_EVENTS", "telegram.events")
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}
	event := events.TelegramUpdate{
		SchemaVersion: "1",
		TenantID:      "11111111-1111-4111-8111-111111111111",
		EventID:       "82373d0f-5740-5f07-b4e8-02c2f4edd824",
		SourceKey:     "telegram:123456:789",
		BotID:         123456,
		UpdateID:      789,
		Payload:       json.RawMessage(`{"update_id":789}`),
	}

	if err := publisher.PublishTelegramUpdate(context.Background(), event); err != nil {
		t.Fatalf("PublishTelegramUpdate() error = %v", err)
	}

	if js.message.Subject != "telegram.events" {
		t.Fatalf("subject = %q, want telegram.events", js.message.Subject)
	}
	if got := js.message.Header.Get(jetstream.MsgIDHeader); got != event.SourceKey {
		t.Fatalf("Nats-Msg-Id = %q, want %q", got, event.SourceKey)
	}
	if got := js.message.Header.Get(jetstream.ExpectedStreamHeader); got != "TELEGRAM_EVENTS" {
		t.Fatalf("Nats-Expected-Stream = %q, want TELEGRAM_EVENTS", got)
	}

	var published events.TelegramUpdate
	if err := json.Unmarshal(js.message.Data, &published); err != nil {
		t.Fatalf("published data is invalid JSON: %v", err)
	}
	if published.EventID != event.EventID || published.SourceKey != event.SourceKey {
		t.Fatalf("published identity = %#v, want %#v", published, event)
	}
}

func TestPublisherReturnsJetStreamFailure(t *testing.T) {
	wantErr := errors.New("no stream leader")
	publisher, err := NewPublisher(&recordingJetStream{err: wantErr}, "TELEGRAM_EVENTS", "telegram.events")
	if err != nil {
		t.Fatalf("NewPublisher() error = %v", err)
	}

	err = publisher.PublishTelegramUpdate(context.Background(), events.TelegramUpdate{SourceKey: "telegram:1:1"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("PublishTelegramUpdate() error = %v, want wrapped %v", err, wantErr)
	}
}
