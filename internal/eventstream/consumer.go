package eventstream

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"antispambee/internal/events"
)

type eventProcessor interface {
	Process(context.Context, events.TelegramUpdate) error
}

// Message is the part of a JetStream message needed by Handler.
type Message interface {
	Data() []byte
	DoubleAck(context.Context) error
	NakWithDelay(time.Duration) error
}

// Handler persists one event before acknowledging it to JetStream.
type Handler struct {
	processor  eventProcessor
	retryDelay time.Duration
}

// NewHandler constructs a durable event handler.
func NewHandler(processor eventProcessor, retryDelay time.Duration) (*Handler, error) {
	if processor == nil {
		return nil, fmt.Errorf("event processor is required")
	}
	if retryDelay <= 0 {
		return nil, fmt.Errorf("retry delay must be positive")
	}
	return &Handler{processor: processor, retryDelay: retryDelay}, nil
}

// Handle decodes and processes a message. Processing failures are negatively
// acknowledged for delayed redelivery; success is acknowledged synchronously.
func (h *Handler) Handle(ctx context.Context, message Message) error {
	var event events.TelegramUpdate
	if err := json.Unmarshal(message.Data(), &event); err != nil {
		return h.nak(message, fmt.Errorf("decode Telegram event: %w", err))
	}

	if err := h.processor.Process(ctx, event); err != nil {
		return h.nak(message, fmt.Errorf("process Telegram event %q: %w", event.SourceKey, err))
	}

	if err := message.DoubleAck(ctx); err != nil {
		return fmt.Errorf("acknowledge Telegram event %q: %w", event.SourceKey, err)
	}
	return nil
}

func (h *Handler) nak(message Message, cause error) error {
	if err := message.NakWithDelay(h.retryDelay); err != nil {
		return fmt.Errorf("%v; request delayed redelivery: %w", cause, err)
	}
	return cause
}
