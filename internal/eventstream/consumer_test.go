package eventstream

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"antispambee/internal/events"
)

type processorStub struct {
	err        error
	processed  []events.TelegramUpdate
	operations *[]string
}

func (p *processorStub) Process(_ context.Context, event events.TelegramUpdate) error {
	p.processed = append(p.processed, event)
	*p.operations = append(*p.operations, "process")
	return p.err
}

type messageStub struct {
	data       []byte
	ackErr     error
	nakErr     error
	ackCount   int
	nakDelays  []time.Duration
	operations *[]string
}

func (m *messageStub) Data() []byte { return m.data }

func (m *messageStub) DoubleAck(context.Context) error {
	m.ackCount++
	*m.operations = append(*m.operations, "ack")
	return m.ackErr
}

func (m *messageStub) NakWithDelay(delay time.Duration) error {
	m.nakDelays = append(m.nakDelays, delay)
	*m.operations = append(*m.operations, "nak")
	return m.nakErr
}

func TestHandlerPersistsBeforeAcknowledging(t *testing.T) {
	operations := []string{}
	processor := &processorStub{operations: &operations}
	message := &messageStub{
		data:       []byte(`{"schema_version":"1","tenant_id":"9d83e552-8910-4c46-b55a-63074078829e","event_id":"82373d0f-5740-5f07-b4e8-02c2f4edd824","source_key":"telegram:123456:789","bot_id":123456,"update_id":789,"payload":{}}`),
		operations: &operations,
	}

	handler, err := NewHandler(processor, time.Second)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	if err := handler.Handle(context.Background(), message); err != nil {
		t.Fatalf("handle message: %v", err)
	}

	if !reflect.DeepEqual(operations, []string{"process", "ack"}) {
		t.Errorf("operations = %v, want process then ack", operations)
	}
	if len(processor.processed) != 1 || processor.processed[0].SourceKey != "telegram:123456:789" {
		t.Fatalf("processed events = %#v", processor.processed)
	}
	if message.ackCount != 1 || len(message.nakDelays) != 0 {
		t.Errorf("ack count = %d, nak delays = %v", message.ackCount, message.nakDelays)
	}
}

func TestHandlerNaksWhenPersistenceFails(t *testing.T) {
	operations := []string{}
	processor := &processorStub{err: errors.New("database unavailable"), operations: &operations}
	message := &messageStub{
		data:       []byte(`{"schema_version":"1","tenant_id":"9d83e552-8910-4c46-b55a-63074078829e","event_id":"82373d0f-5740-5f07-b4e8-02c2f4edd824","source_key":"telegram:123456:789","bot_id":123456,"update_id":789}`),
		operations: &operations,
	}

	handler, err := NewHandler(processor, 3*time.Second)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	if err := handler.Handle(context.Background(), message); err == nil {
		t.Fatal("handle message succeeded, want error")
	}

	if !reflect.DeepEqual(operations, []string{"process", "nak"}) {
		t.Errorf("operations = %v, want process then nak", operations)
	}
	if message.ackCount != 0 || !reflect.DeepEqual(message.nakDelays, []time.Duration{3 * time.Second}) {
		t.Errorf("ack count = %d, nak delays = %v", message.ackCount, message.nakDelays)
	}
}

func TestHandlerNaksMalformedEvent(t *testing.T) {
	operations := []string{}
	processor := &processorStub{operations: &operations}
	message := &messageStub{data: []byte(`{"update_id":`), operations: &operations}

	handler, err := NewHandler(processor, time.Second)
	if err != nil {
		t.Fatalf("create handler: %v", err)
	}
	if err := handler.Handle(context.Background(), message); err == nil {
		t.Fatal("handle malformed event succeeded, want error")
	}

	if len(processor.processed) != 0 || message.ackCount != 0 || len(message.nakDelays) != 1 {
		t.Errorf("processed = %d, ack count = %d, nak delays = %v", len(processor.processed), message.ackCount, message.nakDelays)
	}
}
