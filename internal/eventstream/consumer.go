package eventstream

import (
	"context"
	"encoding/json"
	"errors"
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
	InProgress() error
}

// ProcessedEventStore identifies committed moderation decisions. Commands whose
// replies are sent synchronously must not be reported as complete by this store;
// commands with a committed outbox may be skipped on redelivery.
type ProcessedEventStore interface {
	ModerationEventProcessed(context.Context, events.TelegramUpdate) (bool, error)
}

type HandlerOption func(*Handler)

func WithProcessedEventStore(store ProcessedEventStore) HandlerOption {
	return func(h *Handler) { h.processedEvents = store }
}

// Handler persists one event before acknowledging it to JetStream.
type Handler struct {
	processor         eventProcessor
	retryDelay        time.Duration
	processedEvents   ProcessedEventStore
	progressInterval  time.Duration
	processingTimeout time.Duration
}

// NewHandler constructs a durable event handler.
func NewHandler(processor eventProcessor, retryDelay time.Duration, options ...HandlerOption) (*Handler, error) {
	if processor == nil {
		return nil, fmt.Errorf("event processor is required")
	}
	if retryDelay <= 0 {
		return nil, fmt.Errorf("retry delay must be positive")
	}
	h := &Handler{processor: processor, retryDelay: retryDelay, progressInterval: 10 * time.Second, processingTimeout: 90 * time.Second}
	for _, option := range options {
		option(h)
	}
	return h, nil
}

// Handle decodes and processes a message. Processing failures are negatively
// acknowledged for delayed redelivery; success is acknowledged synchronously.
func (h *Handler) Handle(ctx context.Context, message Message) error {
	var event events.TelegramUpdate
	if err := json.Unmarshal(message.Data(), &event); err != nil {
		return h.nak(message, fmt.Errorf("decode Telegram event: %w", err))
	}

	// Keep the broker's 30-second acknowledgment window alive while external
	// APIs or persistence are running, but bound the entire processing attempt.
	deadlineCtx, deadlineCancel := context.WithTimeout(ctx, h.processingTimeout)
	defer deadlineCancel()
	processingCtx, cancel := context.WithCancelCause(deadlineCtx)
	defer cancel(nil)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(h.progressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-processingCtx.Done():
				return
			case <-ticker.C:
				if err := message.InProgress(); err != nil {
					cancel(fmt.Errorf("extend Telegram event acknowledgment window: %w", err))
					return
				}
			}
		}
	}()
	err := h.process(processingCtx, event)
	close(stop)
	<-done // No progress acknowledgments may race with the terminal ACK/NAK.
	err = errors.Join(err, context.Cause(processingCtx))
	if err != nil {
		return h.nak(message, fmt.Errorf("process Telegram event %q: %w", event.SourceKey, err))
	}

	if err := message.DoubleAck(ctx); err != nil {
		return fmt.Errorf("acknowledge Telegram event %q: %w", event.SourceKey, err)
	}
	return nil
}

func (h *Handler) process(ctx context.Context, event events.TelegramUpdate) error {
	if h.processedEvents != nil {
		processed, err := h.processedEvents.ModerationEventProcessed(ctx, event)
		if err != nil {
			return fmt.Errorf("check committed moderation event: %w", err)
		}
		if processed {
			return nil
		}
	}
	return h.processor.Process(ctx, event)
}

func (h *Handler) nak(message Message, cause error) error {
	if err := message.NakWithDelay(h.retryDelay); err != nil {
		return fmt.Errorf("%v; request delayed redelivery: %w", cause, err)
	}
	return cause
}
