package eventstream

import (
	"context"
	"encoding/json"
	"fmt"

	"antispambee/internal/events"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type jetStreamPublisher interface {
	PublishMsg(context.Context, *nats.Msg, ...jetstream.PublishOpt) (*jetstream.PubAck, error)
}

// Publisher durably publishes moderation source events to JetStream.
type Publisher struct {
	jetStream jetStreamPublisher
	stream    string
	subject   string
}

// NewPublisher validates the immutable JetStream publishing target.
func NewPublisher(js jetStreamPublisher, stream, subject string) (*Publisher, error) {
	if js == nil {
		return nil, fmt.Errorf("JetStream publisher is required")
	}
	if stream == "" {
		return nil, fmt.Errorf("stream name is required")
	}
	if subject == "" {
		return nil, fmt.Errorf("subject is required")
	}

	return &Publisher{jetStream: js, stream: stream, subject: subject}, nil
}

// PublishTelegramUpdate waits for JetStream persistence acknowledgement.
func (p *Publisher) PublishTelegramUpdate(ctx context.Context, event events.TelegramUpdate) error {
	if event.SourceKey == "" {
		return fmt.Errorf("source key is required")
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode Telegram update event: %w", err)
	}

	message := &nats.Msg{
		Subject: p.subject,
		Header:  make(nats.Header),
		Data:    payload,
	}
	message.Header.Set(jetstream.MsgIDHeader, event.SourceKey)
	message.Header.Set(jetstream.ExpectedStreamHeader, p.stream)

	ack, err := p.jetStream.PublishMsg(ctx, message)
	if err != nil {
		return fmt.Errorf("persist Telegram update event: %w", err)
	}
	if ack == nil || ack.Stream != p.stream {
		return fmt.Errorf("unexpected JetStream acknowledgement")
	}

	return nil
}
