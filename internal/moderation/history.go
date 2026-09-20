package moderation

import (
	"antispambee/internal/events"
	"context"
	"fmt"
	"strconv"
	"strings"
)

func (r *CommandRouter) handleHistory(ctx context.Context, event events.TelegramUpdate, c parsedCommand) error {
	if c.ChatType != "private" || c.SenderID <= 0 || c.ChatID != c.SenderID {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Журнал доступен только в личном чате с ботом: /history CHAT_ID")
	}
	chatID, err := strconv.ParseInt(c.Argument, 10, 64)
	if err != nil || chatID >= 0 {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Использование: /history CHAT_ID. Команда для группы указана в /status.")
	}
	policies, err := r.store.ListCommunityPoliciesForModerator(ctx, event.TenantID, c.SenderID)
	if err != nil {
		return err
	}
	linked := false
	for _, p := range policies {
		if p.ChatID == chatID {
			linked = true
		}
	}
	if !linked {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Группа не привязана к вашему аккаунту.")
	}
	status, err := r.telegram.GetChatMemberStatus(ctx, chatID, c.SenderID)
	if err != nil {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Не удалось проверить права администратора. Повторите позже.")
	}
	if status != "creator" && status != "administrator" {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Журнал доступен только действующему администратору группы.")
	}
	entries, err := r.store.ListModerationHistory(ctx, event.TenantID, chatID)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return r.respondToInvalidCommand(ctx, event, c.ChatID, "Сохранённых решений пока нет. Журнал хранит новые случаи 30 дней; старые тексты восстановить нельзя.")
	}
	if err := r.recordCommand(ctx, event, nil); err != nil {
		return err
	}
	// One bounded plain-text response avoids injection and multipart retry duplication.
	var b strings.Builder
	b.WriteString("Последние решения (UTC). Автобан приостановлен.\n")
	for _, entry := range entries {
		e := entry.Evidence
		author := fmt.Sprintf("ID %d", e.Target.UserID)
		if e.AuthorUsername != "" {
			author = "@" + e.AuthorUsername
		}
		text := strings.TrimSpace(strings.Join([]string{e.Message.Text, e.Message.Caption, e.Message.OCRText}, "\n"))
		if text == "" {
			text = "[текст недоступен; решение по контексту]"
		}
		fmt.Fprintf(&b, "\n%s · сообщение %d · %s\n%s · риск %.2f\n%s\n", entry.CreatedAt.UTC().Format("02.01 15:04"), e.Target.MessageID, author, entry.Actions, e.Decision.RiskScore, e.Decision.AuthorizationReason)
		for _, s := range e.Signals {
			if s.Score != nil && *s.Score >= .5 {
				fmt.Fprintf(&b, "%s: %.2f %s\n", s.Detector, *s.Score, boundedHistoryText(strings.Join(s.ReasonCodes, ","), 160))
				if s.EvidenceExcerpt != "" {
					fmt.Fprintf(&b, "Фрагмент, выбранный моделью: %s\n", boundedHistoryText(s.EvidenceExcerpt, 200))
				}
			}
		}
		fmt.Fprintf(&b, "%s\n", boundedHistoryText(text, 350))
	}
	return r.telegram.SendMessage(ctx, c.ChatID, boundedHistoryText(b.String(), 3900))
}

func boundedHistoryText(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
