package moderation

import (
	"context"
	"testing"

	"antispambee/internal/events"
)

type commandStoreStub struct {
	outcome      Outcome
	reportedUser int64
	policyLevel  string
	allowlisted  int64
}

func (s *commandStoreStub) RecordTerminal(_ context.Context, _ events.TelegramUpdate, outcome Outcome) error {
	s.outcome = outcome
	return nil
}
func (s *commandStoreStub) RecordUserReport(_ context.Context, _ string, chatID, reporterID, reportedID, messageID int64) error {
	s.reportedUser = reportedID
	return nil
}
func (s *commandStoreStub) SetCommunityProtection(_ context.Context, _ string, _ int64, level string) error {
	s.policyLevel = level
	return nil
}
func (s *commandStoreStub) SetAllowlisted(_ context.Context, _ string, _ int64, userID, _ int64, allowed bool) error {
	if allowed {
		s.allowlisted = userID
	} else {
		s.allowlisted = 0
	}
	return nil
}
func (s *commandStoreStub) GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error) {
	return CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true}, nil
}

type commandTelegramStub struct {
	status   string
	statuses map[int64]string
	messages []string
}

func (t *commandTelegramStub) GetChatMemberStatus(_ context.Context, _ int64, userID int64) (string, error) {
	if status := t.statuses[userID]; status != "" {
		return status, nil
	}
	return t.status, nil
}
func (t *commandTelegramStub) SendMessage(_ context.Context, _ int64, message string) error {
	t.messages = append(t.messages, message)
	return nil
}

type fallbackStub struct{ calls int }

func (f *fallbackStub) Process(context.Context, events.TelegramUpdate) error {
	f.calls++
	return nil
}

func TestCommandRouterQueuesModeratorBan(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{statuses: map[int64]string{1: "administrator", 42: "member"}}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/ban","reply_to_message":{"message_id":9,"from":{"id":42}}}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.outcome.Action == nil || store.outcome.Action.Type != ActionBanUser || store.outcome.Action.Target.UserID != 42 {
		t.Fatalf("outcome = %#v", store.outcome)
	}
}

func TestCommandRouterRecordsUserReport(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{status: "member"}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, -10099)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/report","reply_to_message":{"message_id":9,"from":{"id":42}}}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.reportedUser != 42 || len(telegram.messages) != 2 {
		t.Fatalf("reported user/messages = %d/%v", store.reportedUser, telegram.messages)
	}
}

func TestCommandRouterQueuesUnbanByUserID(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{statuses: map[int64]string{1: "administrator", 42: "kicked"}}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/unban 42"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.outcome.Action == nil || store.outcome.Action.Type != ActionUnbanUser || store.outcome.Action.Target.UserID != 42 {
		t.Fatalf("outcome = %#v", store.outcome)
	}
}

func TestCommandRouterChangesProtectionLevelForAdmin(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{status: "creator"}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/protection observe"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.policyLevel != "OBSERVE" {
		t.Fatalf("policy level = %q", store.policyLevel)
	}
}

func TestCommandRouterDelegatesNormalMessages(t *testing.T) {
	fallback := &fallbackStub{}
	router, err := NewCommandRouter(&commandStoreStub{}, &commandTelegramStub{}, fallback, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := router.Process(context.Background(), telegramEvent(`{"message":{"text":"hello"}}`)); err != nil {
		t.Fatal(err)
	}
	if fallback.calls != 1 {
		t.Fatalf("fallback calls = %d", fallback.calls)
	}
}
