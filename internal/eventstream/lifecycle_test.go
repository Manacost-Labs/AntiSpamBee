package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"antispambee/internal/events"
)

type processorFunc func(context.Context, events.TelegramUpdate) error

func (f processorFunc) Process(ctx context.Context, event events.TelegramUpdate) error {
	return f(ctx, event)
}

type processedStoreStub struct {
	processed bool
	err       error
	event     events.TelegramUpdate
}

func (s *processedStoreStub) ModerationEventProcessed(_ context.Context, event events.TelegramUpdate) (bool, error) {
	s.event = event
	return s.processed, s.err
}

type lifecycleMessage struct {
	data          []byte
	progress      chan struct{}
	progressErr   error
	ackErr        error
	progressCount atomic.Int32
	terminal      atomic.Bool
	lateProgress  atomic.Bool
	acks          int
	naks          int
}

func (m *lifecycleMessage) Data() []byte { return m.data }
func (m *lifecycleMessage) InProgress() error {
	if m.terminal.Load() {
		m.lateProgress.Store(true)
	}
	m.progressCount.Add(1)
	if m.progress != nil {
		select {
		case m.progress <- struct{}{}:
		default:
		}
	}
	return m.progressErr
}
func (m *lifecycleMessage) DoubleAck(context.Context) error {
	m.terminal.Store(true)
	m.acks++
	return m.ackErr
}
func (m *lifecycleMessage) NakWithDelay(time.Duration) error {
	m.terminal.Store(true)
	m.naks++
	return nil
}

func lifecycleEvent(t *testing.T) (events.TelegramUpdate, []byte) {
	t.Helper()
	identity, err := events.NewTelegramIdentity(123456, 789)
	if err != nil {
		t.Fatal(err)
	}
	event := events.TelegramUpdate{SchemaVersion: "1", TenantID: "9d83e552-8910-4c46-b55a-63074078829e", EventID: identity.EventID, SourceKey: identity.SourceKey, BotID: 123456, UpdateID: 789, Payload: json.RawMessage(`{}`)}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return event, data
}

func TestHandlerMaintainsAckWindowDuringProcessing(t *testing.T) {
	_, data := lifecycleEvent(t)
	message := &lifecycleMessage{data: data, progress: make(chan struct{}, 1)}
	processor := processorFunc(func(ctx context.Context, _ events.TelegramUpdate) error {
		select {
		case <-message.progress:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	handler, err := NewHandler(processor, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	handler.progressInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Handle(ctx, message); err != nil {
		t.Fatal(err)
	}
	if message.progressCount.Load() < 1 || message.acks != 1 || message.naks != 0 || message.lateProgress.Load() {
		t.Fatalf("progress=%d ack=%d nak=%d late=%v", message.progressCount.Load(), message.acks, message.naks, message.lateProgress.Load())
	}
}

func TestHandlerNaksWhenHeartbeatFailsEvenIfProcessorReturnsSuccess(t *testing.T) {
	_, data := lifecycleEvent(t)
	failure := errors.New("connection lost")
	message := &lifecycleMessage{data: data, progressErr: failure}
	processor := processorFunc(func(ctx context.Context, _ events.TelegramUpdate) error {
		<-ctx.Done()
		return nil
	})
	handler, _ := NewHandler(processor, time.Second)
	handler.progressInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Handle(ctx, message); !errors.Is(err, failure) {
		t.Fatalf("Handle() = %v", err)
	}
	if message.acks != 0 || message.naks != 1 || message.lateProgress.Load() {
		t.Fatalf("ack=%d nak=%d late=%v", message.acks, message.naks, message.lateProgress.Load())
	}
}

func TestHandlerBoundsProcessingAttempt(t *testing.T) {
	_, data := lifecycleEvent(t)
	message := &lifecycleMessage{data: data}
	processor := processorFunc(func(ctx context.Context, _ events.TelegramUpdate) error {
		<-ctx.Done()
		return ctx.Err()
	})
	handler, _ := NewHandler(processor, time.Second)
	handler.processingTimeout = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := handler.Handle(ctx, message); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Handle() = %v", err)
	}
	if message.acks != 0 || message.naks != 1 {
		t.Fatalf("ack=%d nak=%d", message.acks, message.naks)
	}
}

func TestHandlerChecksCommittedDecisionBeforeProcessing(t *testing.T) {
	for _, tc := range []struct {
		name        string
		processed   bool
		err         error
		wantProcess int
		wantAck     int
	}{
		{"already committed", true, nil, 0, 1},
		{"new event", false, nil, 1, 1},
		{"store unavailable", false, errors.New("database down"), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event, data := lifecycleEvent(t)
			message := &lifecycleMessage{data: data}
			store := &processedStoreStub{processed: tc.processed, err: tc.err}
			calls := 0
			handler, _ := NewHandler(processorFunc(func(context.Context, events.TelegramUpdate) error { calls++; return nil }), time.Second, WithProcessedEventStore(store))
			err := handler.Handle(context.Background(), message)
			if (err != nil) != (tc.err != nil) || calls != tc.wantProcess || message.acks != tc.wantAck || message.naks != 1-tc.wantAck || store.event.EventID != event.EventID || store.event.TenantID != event.TenantID {
				t.Fatalf("err=%v calls=%d ack=%d nak=%d lookup=%+v", err, calls, message.acks, message.naks, store.event)
			}
		})
	}
}

func TestHandlerRedeliveryAfterLostAckSkipsEnrichment(t *testing.T) {
	_, data := lifecycleEvent(t)
	store := &processedStoreStub{}
	calls := 0
	processor := processorFunc(func(context.Context, events.TelegramUpdate) error { calls++; store.processed = true; return nil })
	handler, _ := NewHandler(processor, time.Second, WithProcessedEventStore(store))
	if err := handler.Handle(context.Background(), &lifecycleMessage{data: data, ackErr: errors.New("ack lost")}); err == nil {
		t.Fatal("expected failed acknowledgment")
	}
	redelivery := &lifecycleMessage{data: data}
	if err := handler.Handle(context.Background(), redelivery); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || redelivery.acks != 1 {
		t.Fatalf("enrichment calls=%d redelivery acks=%d", calls, redelivery.acks)
	}
}
