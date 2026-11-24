package telegramapi

import (
	"context"
	"fmt"
	"strings"
)

type CallbackButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

func (c *Client) SendMessageWithCallbackButtons(ctx context.Context, chatID int64, text string, buttons []CallbackButton) error {
	if chatID == 0 || strings.TrimSpace(text) == "" || len([]rune(text)) > 4096 || len(buttons) == 0 {
		return fmt.Errorf("invalid Telegram review message")
	}
	for _, button := range buttons {
		if strings.TrimSpace(button.Text) == "" || len(button.Data) < 1 || len(button.Data) > 64 {
			return fmt.Errorf("invalid Telegram callback button")
		}
	}
	request := map[string]any{
		"chat_id": chatID, "text": text,
		"link_preview_options": map[string]bool{"is_disabled": true},
		"reply_markup":         map[string]any{"inline_keyboard": [][]CallbackButton{buttons}},
	}
	var sent message
	if err := c.call(ctx, "sendMessage", request, &sent); err != nil {
		return fmt.Errorf("send Telegram review: %w", err)
	}
	return nil
}

func (c *Client) AnswerCallbackQuery(ctx context.Context, callbackID, text string) error {
	var answered bool
	if err := c.call(ctx, "answerCallbackQuery", map[string]string{"callback_query_id": callbackID, "text": text}, &answered); err != nil {
		return fmt.Errorf("answer Telegram callback: %w", err)
	}
	return nil
}
