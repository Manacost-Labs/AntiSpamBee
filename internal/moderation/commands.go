package moderation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/events"
)

const ReasonModeratorCommand = "MODERATOR_COMMAND"

type commandStore interface {
	terminalRecorder
	RecordUserReport(context.Context, string, int64, int64, int64, int64) error
	SetCommunityProtection(context.Context, string, int64, string) error
	SetCommunityModerator(context.Context, string, int64, int64) error
	SetCommunityModeratorSenderChat(context.Context, string, int64, int64, int64) error
	IsAuthorizedSenderChat(context.Context, string, int64, int64) (bool, error)
	SetAllowlisted(context.Context, string, int64, int64, int64, bool) error
	GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error)
	ListCommunityPoliciesForModerator(context.Context, string, int64) ([]CommunityPolicy, error)
	ListModerationHistory(context.Context, string, int64) ([]HistoryEntry, error)
}

type commandTelegram interface {
	GetChatMemberStatus(context.Context, int64, int64) (string, error)
	GetChatTitle(context.Context, int64) (string, error)
	SendMessage(context.Context, int64, string) error
	SendMessageWithURLButton(context.Context, int64, string, string, string) error
}

type eventProcessor interface {
	Process(context.Context, events.TelegramUpdate) error
}

// CommandRouter handles the minimal Telegram-native moderator UI and delegates
// ordinary updates to the detector processor.
type CommandRouter struct {
	store           commandStore
	telegram        commandTelegram
	fallback        eventProcessor
	moderatorChatID int64
	addToGroupURL   string
	now             func() time.Time
}

func NewCommandRouter(
	store commandStore,
	telegram commandTelegram,
	fallback eventProcessor,
	moderatorChatID int64,
	botUsername string,
) (*CommandRouter, error) {
	if store == nil || telegram == nil || fallback == nil {
		return nil, fmt.Errorf("command store, Telegram client, and fallback processor are required")
	}
	addToGroupURL, err := botAddToGroupURL(botUsername)
	if err != nil {
		return nil, err
	}
	return &CommandRouter{
		store: store, telegram: telegram, fallback: fallback,
		moderatorChatID: moderatorChatID, addToGroupURL: addToGroupURL, now: time.Now,
	}, nil
}

func (r *CommandRouter) Process(ctx context.Context, event events.TelegramUpdate) error {
	if chatID, adminID, ok := botAddedToCommunity(event.Payload); ok {
		return r.store.SetCommunityModerator(ctx, event.TenantID, chatID, adminID)
	}
	command, ok := parseCommand(event.Payload)
	if !ok {
		return r.fallback.Process(ctx, event)
	}
	switch command.Name {
	case "start", "help":
		if err := r.recordCommand(ctx, event, nil); err != nil {
			return err
		}
		return r.telegram.SendMessageWithURLButton(
			ctx, command.ChatID, commandHelp(), "➕ Добавить в группу", r.addToGroupURL,
		)
	case "report":
		if command.ReplyUserID <= 0 || command.ReplyMessageID <= 0 {
			return r.respondToInvalidCommand(ctx, event, command.ChatID, "Ответьте командой /report на подозрительное сообщение.")
		}
		if err := r.store.RecordUserReport(ctx, event.TenantID, command.ChatID, command.SenderID, command.ReplyUserID, command.ReplyMessageID); err != nil {
			return fmt.Errorf("record user report: %w", err)
		}
		if err := r.recordCommand(ctx, event, nil); err != nil {
			return err
		}
		if err := r.telegram.SendMessage(ctx, command.ChatID, "Жалоба зарегистрирована и передана модераторам."); err != nil {
			return err
		}
		if r.moderatorChatID != 0 {
			return r.telegram.SendMessage(ctx, r.moderatorChatID, fmt.Sprintf(
				"Новая жалоба: chat=%d, message=%d, user=%d, reporter=%d",
				command.ChatID, command.ReplyMessageID, command.ReplyUserID, command.SenderID,
			))
		}
		return nil
	case "status":
		if command.ChatType == "private" {
			return r.handlePersonalStatus(ctx, event, command)
		}
		if ok, err := r.requireAdmin(ctx, event.TenantID, command); err != nil {
			return err
		} else if !ok {
			return r.respondToInvalidCommand(ctx, event, command.ChatID, "Эта команда доступна только администраторам.")
		}
		policy, err := r.store.GetCommunityPolicy(ctx, event.TenantID, command.ChatID, command.SenderID)
		if err != nil {
			return err
		}
		if err := r.recordCommand(ctx, event, nil); err != nil {
			return err
		}
		return r.telegram.SendMessage(ctx, command.ChatID, fmt.Sprintf(
			"AntiSpamBee: уровень %s, автоматические действия: %t. Автобан приостановлен до подтверждения нарушений.",
			policy.ProtectionLevel, policy.AutomaticActionsEnabled,
		))
	case "link":
		return r.handleLink(ctx, event, command)
	case "history":
		return r.handleHistory(ctx, event, command)
	case "protection":
		return r.handleProtection(ctx, event, command)
	case "allow", "unallow":
		return r.handleAllowlist(ctx, event, command, command.Name == "allow")
	case "ban", "mute", "unban", "warn":
		return r.handleModeratorAction(ctx, event, command)
	default:
		return r.fallback.Process(ctx, event)
	}
}

func (r *CommandRouter) handleLink(ctx context.Context, event events.TelegramUpdate, command parsedCommand) error {
	if command.ChatType == "private" {
		parts := strings.Split(command.Argument, ":")
		chatID, err := strconv.ParseInt(parts[0], 10, 64)
		senderChatID := int64(0)
		if len(parts) == 2 {
			senderChatID, err = strconv.ParseInt(parts[1], 10, 64)
		}
		if err != nil || len(parts) != 2 || chatID == 0 || senderChatID == 0 || command.SenderID <= 0 {
			return r.respondToInvalidCommand(ctx, event, command.ChatID, "Использование: /link CHAT_ID:SENDER_CHAT_ID. Сначала отправьте /link от имени нужной группы.")
		}
		status, err := r.telegram.GetChatMemberStatus(ctx, chatID, command.SenderID)
		if err != nil {
			return r.respondToInvalidCommand(ctx, event, command.ChatID, "Не удалось проверить ваши права в этой группе. Убедитесь, что бот — администратор группы.")
		}
		if status != "administrator" && status != "creator" {
			return r.respondToInvalidCommand(ctx, event, command.ChatID, "Ваш личный аккаунт должен быть администратором этой группы.")
		}
		if err := r.store.SetCommunityModeratorSenderChat(ctx, event.TenantID, chatID, command.SenderID, senderChatID); err != nil {
			return err
		}
		if err := r.recordCommand(ctx, event, nil); err != nil {
			return err
		}
		title, err := r.telegram.GetChatTitle(ctx, chatID)
		if err != nil || strings.TrimSpace(title) == "" {
			title = fmt.Sprintf("Группа %d", chatID)
		}
		return r.telegram.SendMessage(ctx, command.ChatID, "Группа привязана: "+title)
	}
	if (command.ChatType != "group" && command.ChatType != "supergroup") || !command.SentAsChat {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Эту команду отправьте от имени группы.")
	}
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, command.ChatID, fmt.Sprintf(
		"Чтобы привязать эту группу к личному кабинету, отправьте боту в ЛС: /link %d:%d",
		command.ChatID, command.SenderChatID,
	))
}

func (r *CommandRouter) handlePersonalStatus(ctx context.Context, event events.TelegramUpdate, command parsedCommand) error {
	if command.SenderID <= 0 {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Не удалось определить ваш аккаунт Telegram.")
	}
	policies, err := r.store.ListCommunityPoliciesForModerator(ctx, event.TenantID, command.SenderID)
	if err != nil {
		return err
	}
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	if len(policies) == 0 {
		return r.telegram.SendMessage(ctx, command.ChatID, "У вас пока нет подключённых групп. Добавьте бота в группу как администратор.")
	}
	lines := []string{"Ваши группы:"}
	for _, policy := range policies {
		title, err := r.telegram.GetChatTitle(ctx, policy.ChatID)
		if err != nil || strings.TrimSpace(title) == "" {
			title = fmt.Sprintf("Группа %d", policy.ChatID)
		}
		lines = append(lines, fmt.Sprintf(
			"%s: уровень %s, автоматические действия: %t. Автобан приостановлен до подтверждения нарушений.\nЖурнал: /history %d",
			title, policy.ProtectionLevel, policy.AutomaticActionsEnabled, policy.ChatID,
		))
	}
	return r.telegram.SendMessage(ctx, command.ChatID, strings.Join(lines, "\n"))
}

func botAddedToCommunity(payload json.RawMessage) (int64, int64, bool) {
	type user struct {
		ID int64 `json:"id"`
	}
	type member struct {
		Status string `json:"status"`
	}
	var update struct {
		MyChatMember *struct {
			From *user `json:"from"`
			Chat *struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
			OldChatMember *member `json:"old_chat_member"`
			NewChatMember *member `json:"new_chat_member"`
		} `json:"my_chat_member"`
	}
	if json.Unmarshal(payload, &update) != nil || update.MyChatMember == nil ||
		update.MyChatMember.From == nil || update.MyChatMember.Chat == nil ||
		update.MyChatMember.OldChatMember == nil || update.MyChatMember.NewChatMember == nil {
		return 0, 0, false
	}
	change := update.MyChatMember
	if change.From.ID <= 0 || change.Chat.ID == 0 ||
		(change.Chat.Type != "group" && change.Chat.Type != "supergroup" && change.Chat.Type != "channel") ||
		(change.OldChatMember.Status != "left" && change.OldChatMember.Status != "kicked") ||
		(change.NewChatMember.Status != "member" && change.NewChatMember.Status != "administrator") {
		return 0, 0, false
	}
	return change.Chat.ID, change.From.ID, true
}

type parsedCommand struct {
	Name           string
	Argument       string
	ChatID         int64
	ChatType       string
	SenderID       int64
	SenderChatID   int64
	SenderChatType string
	SentAsChat     bool
	MessageID      int64
	ReplyUserID    int64
	ReplyMessageID int64
}

func parseCommand(payload json.RawMessage) (parsedCommand, bool) {
	type user struct {
		ID int64 `json:"id"`
	}
	type chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	}
	type reply struct {
		MessageID int64 `json:"message_id"`
		From      *user `json:"from"`
	}
	var update struct {
		Message *struct {
			MessageID      int64  `json:"message_id"`
			Text           string `json:"text"`
			From           *user  `json:"from"`
			Chat           *chat  `json:"chat"`
			SenderChat     *chat  `json:"sender_chat"`
			ReplyToMessage *reply `json:"reply_to_message"`
		} `json:"message"`
	}
	if json.Unmarshal(payload, &update) != nil || update.Message == nil || update.Message.Chat == nil {
		return parsedCommand{}, false
	}
	// Telegram represents an anonymous administrator as sender_chat. Depending
	// on the client and linked-discussion setup that identity may be the current
	// group, another group, or its channel; all three are intentional group-side
	// moderator commands.
	sentAsChat := update.Message.SenderChat != nil && update.Message.SenderChat.ID != 0
	if update.Message.From == nil && !sentAsChat {
		return parsedCommand{}, false
	}
	fields := strings.Fields(strings.TrimSpace(update.Message.Text))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return parsedCommand{}, false
	}
	name := strings.TrimPrefix(strings.SplitN(fields[0], "@", 2)[0], "/")
	command := parsedCommand{
		Name: strings.ToLower(name), ChatID: update.Message.Chat.ID,
		ChatType: update.Message.Chat.Type, SentAsChat: sentAsChat, MessageID: update.Message.MessageID,
	}
	if update.Message.From != nil {
		command.SenderID = update.Message.From.ID
	}
	if update.Message.SenderChat != nil {
		command.SenderChatID = update.Message.SenderChat.ID
		command.SenderChatType = update.Message.SenderChat.Type
	}
	if len(fields) > 1 {
		command.Argument = strings.ToUpper(fields[1])
	}
	if reply := update.Message.ReplyToMessage; reply != nil && reply.From != nil {
		command.ReplyUserID = reply.From.ID
		command.ReplyMessageID = reply.MessageID
	}
	slog.Info("moderator command received",
		"command", command.Name,
		"chat_type", command.ChatType,
		"sent_as_chat", command.SentAsChat,
		"sender_chat_id", command.SenderChatID,
		"sender_chat_type", command.SenderChatType,
	)
	return command, true
}

func (r *CommandRouter) handleProtection(ctx context.Context, event events.TelegramUpdate, command parsedCommand) error {
	if ok, err := r.requireAdmin(ctx, event.TenantID, command); err != nil {
		return err
	} else if !ok {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Эта команда доступна только администраторам.")
	}
	valid := map[string]bool{"OBSERVE": true, "SOFT": true, "STANDARD": true, "STRICT": true}
	if !valid[command.Argument] {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Использование: /protection observe|soft|standard|strict")
	}
	if err := r.store.SetCommunityProtection(ctx, event.TenantID, command.ChatID, command.Argument); err != nil {
		return err
	}
	if command.SenderID > 0 && command.SenderChatID == 0 {
		if err := r.store.SetCommunityModerator(ctx, event.TenantID, command.ChatID, command.SenderID); err != nil {
			return err
		}
	}
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, command.ChatID, "Уровень защиты установлен: "+command.Argument)
}

func (r *CommandRouter) handleAllowlist(ctx context.Context, event events.TelegramUpdate, command parsedCommand, allowed bool) error {
	if ok, err := r.requireAdmin(ctx, event.TenantID, command); err != nil {
		return err
	} else if !ok {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Эта команда доступна только администраторам.")
	}
	if command.ReplyUserID <= 0 {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Ответьте этой командой на сообщение пользователя.")
	}
	if err := r.store.SetAllowlisted(ctx, event.TenantID, command.ChatID, command.ReplyUserID, command.SenderID, allowed); err != nil {
		return err
	}
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, command.ChatID, "Allowlist обновлён.")
}

func (r *CommandRouter) handleModeratorAction(ctx context.Context, event events.TelegramUpdate, command parsedCommand) error {
	if ok, err := r.requireAdmin(ctx, event.TenantID, command); err != nil {
		return err
	} else if !ok {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Эта команда доступна только администраторам.")
	}
	targetUserID := command.ReplyUserID
	targetMessageID := command.ReplyMessageID
	if command.Name == "unban" && targetUserID <= 0 {
		parsed, err := strconv.ParseInt(command.Argument, 10, 64)
		if err == nil && parsed > 0 {
			targetUserID = parsed
			targetMessageID = command.MessageID
		}
	}
	if targetUserID <= 0 || targetMessageID <= 0 {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Ответьте этой командой на сообщение пользователя.")
	}
	status, err := r.telegram.GetChatMemberStatus(ctx, command.ChatID, targetUserID)
	if err != nil {
		return err
	}
	if command.Name != "unban" && (status == "administrator" || status == "creator") {
		return r.respondToInvalidCommand(ctx, event, command.ChatID, "Нельзя применить действие к администратору или владельцу.")
	}
	if command.Name == "warn" {
		if err := r.recordCommand(ctx, event, nil); err != nil {
			return err
		}
		return r.telegram.SendMessage(ctx, command.ChatID, fmt.Sprintf("Предупреждение пользователю %d от модератора.", targetUserID))
	}
	actionType := ActionBanUser
	untilDate := int64(0)
	if command.Name == "mute" {
		actionType = ActionMuteUser
		untilDate = r.now().Add(time.Hour).Unix()
	}
	if command.Name == "unban" {
		actionType = ActionUnbanUser
	}
	target := ActionTarget{
		Kind: TargetMessage, ChatID: command.ChatID,
		UserID: targetUserID, MessageID: targetMessageID,
	}
	action := &ActionRequest{
		Type: actionType, Target: target, UntilDate: untilDate,
		IdempotencyKey: actionIdempotencyKey(event.EventID, actionType, target),
	}
	if err := r.recordCommand(ctx, event, action); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, command.ChatID, "Действие поставлено в безопасную очередь.")
}

func (r *CommandRouter) requireAdmin(ctx context.Context, tenantID string, command parsedCommand) (bool, error) {
	if command.ChatType != "group" && command.ChatType != "supergroup" {
		return false, nil
	}
	if command.SentAsChat {
		return r.store.IsAuthorizedSenderChat(ctx, tenantID, command.ChatID, command.SenderChatID)
	}
	if command.SenderID <= 0 {
		return false, nil
	}
	status, err := r.telegram.GetChatMemberStatus(ctx, command.ChatID, command.SenderID)
	if err != nil {
		return false, err
	}
	return status == "administrator" || status == "creator", nil
}

func (r *CommandRouter) respondToInvalidCommand(ctx context.Context, event events.TelegramUpdate, chatID int64, message string) error {
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, chatID, message)
}

func (r *CommandRouter) recordCommand(ctx context.Context, event events.TelegramUpdate, action *ActionRequest) error {
	score, confidence := 0.0, 1.0
	signal := detection.Signal{
		SchemaVersion: "1", Detector: "system.command", DetectorVersion: "command-v1",
		Category: "system.command", Status: detection.StatusAvailable,
		Score: &score, Confidence: &confidence, Severity: detection.SeverityInfo,
		EvidenceCoverage: 1, ReasonCodes: []string{ReasonModeratorCommand},
		MatchedRules: []string{}, CreatedAt: r.now().UTC(),
	}
	decision := Decision{
		RiskScore: 0, DecisionConfidence: 1, EvidenceCoverage: 1,
		RecommendedAction: ActionAllow, AuthorizedAction: ActionAllow,
		AuthorizationReason: ReasonModeratorCommand,
	}
	state := ProcessedAllow
	if action != nil {
		state = DecidedPendingAction
		decision.RecommendedAction = action.Type
		decision.AuthorizedAction = action.Type
	}
	actions := []ActionRequest{}
	if action != nil {
		actions = actionRequestsFor(event.EventID, action.Type, action.Target)
		for index := range actions {
			if actions[index].Type == action.Type {
				actions[index].UntilDate = action.UntilDate
			}
		}
	}
	var evidence *Evidence
	if action != nil {
		var update struct {
			Message struct {
				Reply json.RawMessage `json:"reply_to_message"`
			} `json:"message"`
		}
		_ = json.Unmarshal(event.Payload, &update)
		reply, _ := json.Marshal(struct {
			Message json.RawMessage `json:"message"`
		}{update.Message.Reply})
		evidence = newEvidence(action.Target, messageContent(reply), detection.Profile{}, []detection.Signal{signal}, decision, CommunityPolicy{}, false)
		evidence.AuthorUsername = messageAuthorUsername(reply)
	}
	return r.store.RecordTerminal(ctx, event, Outcome{
		State: state, Signals: []detection.Signal{signal}, Decision: decision, Actions: actions, Evidence: evidence,
	})
}

func commandHelp() string {
	return `🐝 AntiSpamBee — защита группы от рекламы и спама.

Для участников:
/report — пожаловаться ответом на сообщение
/help — открыть этот справочник

Для администраторов:
/status — текущий режим защиты
/history CHAT_ID — последние решения и сообщения (в ЛС, хранение 30 дней)
/link — привязать группу к личному кабинету
/protection observe — только наблюдение
/protection soft — ручная модерация
/protection standard — удаление рекламы без автобана
/protection strict — удаление явной рекламы; автобан пока приостановлен
/allow и /unallow — добавить или убрать автора из исключений
/warn — предупредить автора
/mute — ограничить автора на 1 час
/ban — заблокировать автора
/unban USER_ID — снять блокировку

/report, /allow, /unallow, /warn, /mute и /ban отправляйте ответом на сообщение пользователя.`
}

func botAddToGroupURL(username string) (string, error) {
	if len(username) < 5 || len(username) > 32 {
		return "", fmt.Errorf("valid Telegram bot username is required")
	}
	for _, char := range username {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_' {
			continue
		}
		return "", fmt.Errorf("valid Telegram bot username is required")
	}
	return "https://t.me/" + username + "?startgroup=setup&admin=delete_messages+restrict_members", nil
}
