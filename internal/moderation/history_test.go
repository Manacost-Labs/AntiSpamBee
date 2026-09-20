package moderation

import (
	"antispambee/internal/detection"
	"context"
	"strings"
	"testing"
)

func TestHistoryChecksCurrentAdminAndBindingBeforeReading(t *testing.T) {
	for _, tc := range []struct {
		name, status    string
		linked, allowed bool
	}{
		{"current admin", "administrator", true, true},
		{"former admin", "member", true, false},
		{"unlinked admin", "administrator", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &commandStoreStub{history: []HistoryEntry{{Evidence: Evidence{Message: detection.MessageContent{Text: "saved ad"}}}}}
			if tc.linked {
				store.personalPolicies = []CommunityPolicy{{ChatID: -1001}}
			}
			tg := &commandTelegramStub{status: tc.status}
			r, err := NewCommandRouter(store, tg, &fallbackStub{}, 0, "AntiSpamBeeBot")
			if err != nil {
				t.Fatal(err)
			}
			err = r.Process(context.Background(), telegramEvent(`{"message":{"from":{"id":9},"chat":{"id":9,"type":"private"},"text":"/history -1001"}}`))
			if err != nil {
				t.Fatal(err)
			}
			if store.historyRead != tc.allowed || strings.Contains(strings.Join(tg.messages, ""), "saved ad") != tc.allowed {
				t.Fatalf("read=%v messages=%v", store.historyRead, tg.messages)
			}
		})
	}
}
