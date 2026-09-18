package moderation

import (
	"context"
	"encoding/json"
	"fmt"
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
	SetAllowlisted(context.Context, string, int64, int64, int64, bool) error
	GetCommunityPolicy(context.Context, string, int64, int64) (CommunityPolicy, error)
}

type commandTelegram interface {
	GetChatMemberStatus(context.Context, int64, int64) (string, error)
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
		if ok, err := r.requireAdmin(ctx, command); err != nil {
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
			"AntiSpamBee: уровень %s, автоматические действия: %t, автобан: %t",
			policy.ProtectionLevel, policy.AutomaticActionsEnabled, policy.AutobanEnabled,
		))
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

type parsedCommand struct {
	Name           string
	Argument       string
	ChatID         int64
	ChatType       string
	SenderID       int64
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
			ReplyToMessage *reply `json:"reply_to_message"`
		} `json:"message"`
	}
	if json.Unmarshal(payload, &update) != nil || update.Message == nil ||
		update.Message.From == nil || update.Message.Chat == nil {
		return parsedCommand{}, false
	}
	fields := strings.Fields(strings.TrimSpace(update.Message.Text))
	if len(fields) == 0 || !strings.HasPrefix(fields[0], "/") {
		return parsedCommand{}, false
	}
	name := strings.TrimPrefix(strings.SplitN(fields[0], "@", 2)[0], "/")
	command := parsedCommand{
		Name: strings.ToLower(name), ChatID: update.Message.Chat.ID,
		ChatType: update.Message.Chat.Type, SenderID: update.Message.From.ID,
		MessageID: update.Message.MessageID,
	}
	if len(fields) > 1 {
		command.Argument = strings.ToUpper(fields[1])
	}
	if reply := update.Message.ReplyToMessage; reply != nil && reply.From != nil {
		command.ReplyUserID = reply.From.ID
		command.ReplyMessageID = reply.MessageID
	}
	return command, true
}

func (r *CommandRouter) handleProtection(ctx context.Context, event events.TelegramUpdate, command parsedCommand) error {
	if ok, err := r.requireAdmin(ctx, command); err != nil {
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
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	return r.telegram.SendMessage(ctx, command.ChatID, "Уровень защиты установлен: "+command.Argument)
}

func (r *CommandRouter) handleAllowlist(ctx context.Context, event events.TelegramUpdate, command parsedCommand, allowed bool) error {
	if ok, err := r.requireAdmin(ctx, command); err != nil {
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
	if ok, err := r.requireAdmin(ctx, command); err != nil {
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

func (r *CommandRouter) requireAdmin(ctx context.Context, command parsedCommand) (bool, error) {
	if command.ChatType != "group" && command.ChatType != "supergroup" {
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
	return r.store.RecordTerminal(ctx, event, Outcome{
		State: state, Signals: []detection.Signal{signal}, Decision: decision, Actions: actions,
	})
}

func commandHelp() string {
	return `🐝 AntiSpamBee — защита группы от рекламы и спама.

Для участников:
/report — пожаловаться ответом на сообщение
/help — открыть этот справочник

Для администраторов:
/status — текущий режим защиты
/protection observe — только наблюдение
/protection soft — ручная модерация
/protection standard — удаление рекламы без автобана
/protection strict — удаление и автобан при риске 100%
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
