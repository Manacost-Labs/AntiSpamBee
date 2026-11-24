package moderation

import (
	"context"
	"errors"
	"testing"

	"antispambee/internal/events"
)

func TestProtectionCommandQueuesReplyWithoutCallingTelegram(t *testing.T) {
	store := &commandStoreStub{}
	tg := &commandTelegramStub{status: "creator"}
	router, err := NewCommandRouter(store, tg, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/protection strict"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.outcome.Command == nil || len(store.outcome.Command.Replies) != 1 || len(tg.messages) != 0 || store.policyLevel != "STRICT" {
		t.Fatalf("outcome=%+v telegram=%+v", store.outcome, tg)
	}
	store.policyLevel = "OBSERVE"
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.policyLevel != "OBSERVE" {
		t.Fatal("replay overwrote newer policy")
	}
}

func TestProtectionCommandPersistenceFailureDoesNotChangeSettings(t *testing.T) {
	failure := errors.New("database unavailable")
	store := &commandStoreStub{policyLevel: "OBSERVE", moderatorID: 9, recordErr: failure}
	tg := &commandTelegramStub{status: "creator"}
	router, err := NewCommandRouter(store, tg, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/protection strict"}}`)
	if err := router.Process(context.Background(), event); !errors.Is(err, failure) {
		t.Fatalf("Process()=%v", err)
	}
	if store.policyLevel != "OBSERVE" || store.moderatorID != 9 || len(tg.messages) != 0 || len(store.commandCommits) != 0 {
		t.Fatal("failed persistence applied command effects")
	}
}

func commandEventWithID(t *testing.T, payload string, updateID int64) events.TelegramUpdate {
	t.Helper()
	event := telegramEvent(payload)
	identity, err := events.NewTelegramIdentity(event.BotID, updateID)
	if err != nil {
		t.Fatal(err)
	}
	event.EventID, event.SourceKey, event.UpdateID = identity.EventID, identity.SourceKey, updateID
	return event
}

func TestAllowlistReplayDoesNotUndoLaterUnallow(t *testing.T) {
	store := &commandStoreStub{}
	tg := &commandTelegramStub{status: "creator"}
	router, err := NewCommandRouter(store, tg, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	allow := commandEventWithID(t, `{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/allow","reply_to_message":{"message_id":9,"from":{"id":42}}}}`, 10001)
	unallow := commandEventWithID(t, `{"message":{"message_id":11,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/unallow","reply_to_message":{"message_id":9,"from":{"id":42}}}}`, 10002)
	for _, event := range []events.TelegramUpdate{allow, unallow, allow} {
		if err := router.Process(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if store.allowlisted != 0 || len(tg.messages) != 0 {
		t.Fatal("old allow command changed current state or sent reply directly")
	}
}

func TestAnonymousAllowlistCommandRecordsSenderChat(t *testing.T) {
	store := &commandStoreStub{senderChats: map[int64]bool{-1001: true}}
	router, err := NewCommandRouter(store, &commandTelegramStub{}, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"sender_chat":{"id":-1001,"type":"supergroup"},"chat":{"id":-1001,"type":"supergroup"},"text":"/allow","reply_to_message":{"message_id":9,"from":{"id":42}}}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.outcome.Command == nil || store.outcome.Command.Mutation.Allowlist.AddedBy != -1001 {
		t.Fatal("anonymous command actor was lost")
	}
}
