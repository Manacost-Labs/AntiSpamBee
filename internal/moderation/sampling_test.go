package moderation

import (
	"antispambee/internal/detection"
	"context"
	"fmt"
	"testing"
)

func TestEvaluationSampleIsStableAndBounded(t *testing.T) {
	count := 0
	for i := 0; i < 10000; i++ {
		id := fmt.Sprintf("event-%d", i)
		got := evaluationSample("tenant", id)
		if got != evaluationSample("tenant", id) {
			t.Fatal("unstable sample")
		}
		if got {
			count++
		}
	}
	if count < 400 || count > 600 {
		t.Fatalf("sample size=%d expected approximately 5%%", count)
	}
	if evaluationSample("tenant", "") {
		t.Fatal("empty event ID sampled")
	}
}

func TestProcessorSamplesAllowedMessagesWithoutActions(t *testing.T) {
	store := &recordingStore{}
	p, err := NewProcessor(store, &profileFetcherStub{}, detection.NewProfileDetector())
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":5,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":"Привет!"}}`)
	for i := 0; i < 100; i++ {
		event.EventID = fmt.Sprintf("sample-%d", i)
		if err := p.Process(context.Background(), event); err != nil {
			t.Fatal(err)
		}
		want := evaluationSample(event.TenantID, event.EventID)
		if (store.outcome.Evidence != nil) != want {
			t.Fatal("incorrect archive selection")
		}
		if want && !store.outcome.Evidence.EvaluationSample {
			t.Fatal("sample marker missing")
		}
		if len(store.outcome.Actions) != 0 || store.outcome.Decision.AuthorizedAction != ActionAllow {
			t.Fatal("sampling changed moderation")
		}
	}
	private := telegramEvent(`{"message":{"message_id":5,"from":{"id":42},"chat":{"id":42,"type":"private"},"text":"Привет!"}}`)
	for i := 0; i < 100; i++ {
		private.EventID = fmt.Sprintf("sample-%d", i)
		if err := p.Process(context.Background(), private); err != nil {
			t.Fatal(err)
		}
		if store.outcome.Evidence != nil {
			t.Fatal("private message included in group evaluation sample")
		}
	}
}
