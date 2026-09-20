package moderation

import (
	"context"
	"strings"
	"testing"

	"antispambee/internal/events"
)

type commandStoreStub struct {
	outcome          Outcome
	reportedUser     int64
	policyLevel      string
	allowlisted      int64
	moderatorID      int64
	senderChats      map[int64]bool
	personalPolicies []CommunityPolicy
	history          []HistoryEntry
	historyRead      bool
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
func (s *commandStoreStub) SetCommunityModerator(_ context.Context, _ string, _ int64, moderatorID int64) error {
	s.moderatorID = moderatorID
	return nil
}
func (s *commandStoreStub) SetCommunityModeratorSenderChat(_ context.Context, _ string, _ int64, moderatorID, _ int64) error {
	s.moderatorID = moderatorID
	return nil
}
func (s *commandStoreStub) IsAuthorizedSenderChat(_ context.Context, _ string, _, senderChatID int64) (bool, error) {
	return s.senderChats[senderChatID], nil
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
func (s *commandStoreStub) ListCommunityPoliciesForModerator(context.Context, string, int64) ([]CommunityPolicy, error) {
	return s.personalPolicies, nil
}
func (s *commandStoreStub) ListModerationHistory(context.Context, string, int64) ([]HistoryEntry, error) {
	s.historyRead = true
	return s.history, nil
}

type commandTelegramStub struct {
	status     string
	statuses   map[int64]string
	chatTitles map[int64]string
	messages   []string
	buttonText string
	buttonURL  string
}

func (t *commandTelegramStub) GetChatMemberStatus(_ context.Context, _ int64, userID int64) (string, error) {
	if status := t.statuses[userID]; status != "" {
		return status, nil
	}
	return t.status, nil
}
func (t *commandTelegramStub) GetChatTitle(_ context.Context, chatID int64) (string, error) {
	return t.chatTitles[chatID], nil
}
func (t *commandTelegramStub) SendMessage(_ context.Context, _ int64, message string) error {
	t.messages = append(t.messages, message)
	return nil
}
func (t *commandTelegramStub) SendMessageWithURLButton(_ context.Context, _ int64, message, buttonText, buttonURL string) error {
	t.messages = append(t.messages, message)
	t.buttonText = buttonText
	t.buttonURL = buttonURL
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
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/ban","reply_to_message":{"message_id":9,"from":{"id":42}}}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if !hasAction(store.outcome, ActionBanUser) || !hasAction(store.outcome, ActionDeleteMessage) {
		t.Fatalf("outcome = %#v", store.outcome)
	}
}

func TestCommandRouterRecordsUserReport(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{status: "member"}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, -10099, "AntiSpamBeeBot")
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
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":-1001,"type":"supergroup"},"text":"/unban 42"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if !hasAction(store.outcome, ActionUnbanUser) {
		t.Fatalf("outcome = %#v", store.outcome)
	}
}

func TestCommandRouterChangesProtectionLevelForAdmin(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{status: "creator"}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
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
	if store.moderatorID != 1 {
		t.Fatalf("moderator ID = %d, want 1", store.moderatorID)
	}
}

func TestCommandRouterChangesProtectionLevelForAnonymousAdmin(t *testing.T) {
	store := &commandStoreStub{moderatorID: 9, senderChats: map[int64]bool{-1001: true}}
	telegram := &commandTelegramStub{}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 10,
			"from": {"id":1087968824,"is_bot":true},
			"sender_chat": {"id": -1001, "type": "supergroup"},
			"chat": {"id": -1001, "type": "supergroup"},
			"text": "/protection strict"
		}
	}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.policyLevel != "STRICT" {
		t.Fatalf("policy level = %q", store.policyLevel)
	}
	if store.moderatorID != 9 {
		t.Fatalf("anonymous Telegram identity replaced moderator: %d", store.moderatorID)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "STRICT") {
		t.Fatalf("messages = %q", telegram.messages)
	}
}

func TestCommandRouterChangesProtectionLevelForLinkedChannelIdentity(t *testing.T) {
	store := &commandStoreStub{senderChats: map[int64]bool{-1002: true}}
	telegram := &commandTelegramStub{}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"message": {
			"message_id": 10,
			"sender_chat": {"id": -1002, "type": "channel"},
			"chat": {"id": -1001, "type": "supergroup"},
			"text": "/protection strict"
		}
	}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.policyLevel != "STRICT" {
		t.Fatalf("policy level = %q", store.policyLevel)
	}
}

func TestCommandRouterRejectsUnlinkedChannelIdentity(t *testing.T) {
	store := &commandStoreStub{senderChats: map[int64]bool{-1002: false}}
	telegram := &commandTelegramStub{}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"sender_chat":{"id":-1002,"type":"channel"},"chat":{"id":-1001,"type":"supergroup"},"text":"/protection observe"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.policyLevel != "" || len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "только администраторам") {
		t.Fatalf("policy/messages = %q/%q", store.policyLevel, telegram.messages)
	}
}

func TestCommandRouterShowsAttachedGroupStatusInPrivateChat(t *testing.T) {
	store := &commandStoreStub{personalPolicies: []CommunityPolicy{{
		ChatID: -1001, ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true,
	}}}
	telegram := &commandTelegramStub{chatTitles: map[int64]string{-1001: "Группа Рейд"}}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":1,"type":"private"},"text":"/status"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "Группа Рейд") || !strings.Contains(telegram.messages[0], "STRICT") {
		t.Fatalf("messages = %q", telegram.messages)
	}
}

func TestCommandRouterLinksGroupFromPrivateChatAfterAdminCheck(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{
		statuses:   map[int64]string{1: "administrator"},
		chatTitles: map[int64]string{-1002: "Вторая группа"},
	}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":1,"type":"private"},"text":"/link -1002:-1003"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.moderatorID != 1 {
		t.Fatalf("moderator ID = %d", store.moderatorID)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "Вторая группа") {
		t.Fatalf("messages = %q", telegram.messages)
	}
}

func TestCommandRouterShowsLinkInstructionForAnonymousGroupAdmin(t *testing.T) {
	store := &commandStoreStub{}
	telegram := &commandTelegramStub{}
	router, err := NewCommandRouter(store, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"sender_chat":{"id":-1002,"type":"channel"},"chat":{"id":-1002,"type":"supergroup"},"text":"/link"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "/link -1002:-1002") {
		t.Fatalf("messages = %q", telegram.messages)
	}
}

func TestCommandRouterDelegatesNormalMessages(t *testing.T) {
	fallback := &fallbackStub{}
	router, err := NewCommandRouter(&commandStoreStub{}, &commandTelegramStub{}, fallback, 0, "AntiSpamBeeBot")
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

func TestCommandRouterRecordsAdminWhoAddsBotToCommunity(t *testing.T) {
	store := &commandStoreStub{}
	router, err := NewCommandRouter(store, &commandTelegramStub{}, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"my_chat_member": {
			"from": {"id": 9001},
			"chat": {"id": -100777, "type": "supergroup"},
			"old_chat_member": {"status": "left"},
			"new_chat_member": {"status": "member"}
		}
	}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.moderatorID != 9001 {
		t.Fatalf("moderator ID = %d, want 9001", store.moderatorID)
	}
}

func TestCommandRouterRecordsAdminWhoAddsBotToChannel(t *testing.T) {
	store := &commandStoreStub{}
	router, err := NewCommandRouter(store, &commandTelegramStub{}, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{
		"my_chat_member": {
			"from": {"id": 9001},
			"chat": {"id": -100777, "type": "channel"},
			"old_chat_member": {"status": "left"},
			"new_chat_member": {"status": "administrator"}
		}
	}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if store.moderatorID != 9001 {
		t.Fatalf("moderator ID = %d, want 9001", store.moderatorID)
	}
}

func TestCommandRouterStartOffersAdminInstallAndCommandGuide(t *testing.T) {
	telegram := &commandTelegramStub{}
	router, err := NewCommandRouter(&commandStoreStub{}, telegram, &fallbackStub{}, 0, "AntiSpamBeeBot")
	if err != nil {
		t.Fatal(err)
	}
	event := telegramEvent(`{"message":{"message_id":10,"from":{"id":1},"chat":{"id":1,"type":"private"},"text":"/start"}}`)
	if err := router.Process(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "/protection strict") || !strings.Contains(telegram.messages[0], "/report") {
		t.Fatalf("help message = %q", telegram.messages)
	}
	if telegram.buttonText != "➕ Добавить в группу" || telegram.buttonURL != "https://t.me/AntiSpamBeeBot?startgroup=setup&admin=delete_messages+restrict_members" {
		t.Fatalf("button = %q %q", telegram.buttonText, telegram.buttonURL)
	}
}

func TestCommandRouterRejectsUnsafeBotUsername(t *testing.T) {
	_, err := NewCommandRouter(
		&commandStoreStub{}, &commandTelegramStub{}, &fallbackStub{}, 0,
		"AntiSpamBeeBot?startgroup=x",
	)
	if err == nil {
		t.Fatal("NewCommandRouter() accepted an unsafe bot username")
	}
}
