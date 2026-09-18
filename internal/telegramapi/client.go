package telegramapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"antispambee/internal/detection"
)

const profilePostLimit = 5

// ClientConfig configures Telegram Bot API access.
type ClientConfig struct {
	Token      string
	BaseURL    string
	HTTPClient *http.Client
}

// Client fetches the optional profile context used by detectors.
type Client struct {
	token      string
	baseURL    string
	httpClient *http.Client
}

// APIError is a structured Telegram failure suitable for retry decisions.
type APIError struct {
	ErrorCode   int
	Description string
	RetryAfter  time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Telegram API error %d: %s", e.ErrorCode, e.Description)
}

// NewClient creates a Bot API client without making a network request.
func NewClient(config ClientConfig) (*Client, error) {
	if config.Token == "" {
		return nil, fmt.Errorf("Telegram bot token is required")
	}
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || !safeAPIBaseURL(parsedURL) {
		return nil, fmt.Errorf("Telegram API base URL is invalid")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	return &Client{
		token:      config.Token,
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}, nil
}

func safeAPIBaseURL(value *url.URL) bool {
	if value == nil || value.Host == "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	if value.Scheme != "http" {
		return false
	}
	host := value.Hostname()
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

// FetchProfile gets a user's bio, personal channel metadata, and five recent
// personal-channel messages. Missing personal channels are not errors.
func (c *Client) FetchProfile(ctx context.Context, userID int64) (detection.Profile, error) {
	if userID <= 0 {
		return detection.Profile{}, fmt.Errorf("Telegram user ID must be positive")
	}

	var userChat chatFullInfo
	if err := c.call(ctx, "getChat", struct {
		ChatID int64 `json:"chat_id"`
	}{ChatID: userID}, &userChat); err != nil {
		return detection.Profile{}, fmt.Errorf("get Telegram user profile: %w", err)
	}

	profile := detection.Profile{Username: userChat.Username, Bio: userChat.Bio}
	if userChat.PersonalChat == nil {
		return profile, nil
	}

	var channel chatFullInfo
	if err := c.call(ctx, "getChat", struct {
		ChatID int64 `json:"chat_id"`
	}{ChatID: userChat.PersonalChat.ID}, &channel); err != nil {
		return detection.Profile{}, fmt.Errorf("get Telegram personal channel: %w", err)
	}

	var messages []message
	if err := c.call(ctx, "getUserPersonalChatMessages", struct {
		UserID int64 `json:"user_id"`
		Limit  int   `json:"limit"`
	}{UserID: userID, Limit: profilePostLimit}, &messages); err != nil {
		return detection.Profile{}, fmt.Errorf("get Telegram personal channel messages: %w", err)
	}

	posts := make([]string, 0, len(messages))
	for _, message := range messages {
		text := message.Text
		if text == "" {
			text = message.Caption
		}
		if text != "" {
			posts = append(posts, text)
		}
	}
	profile.PersonalChannel = &detection.PersonalChannel{
		Title:       firstNonEmpty(channel.Title, userChat.PersonalChat.Title),
		Username:    firstNonEmpty(channel.Username, userChat.PersonalChat.Username),
		Description: channel.Description,
		RecentPosts: posts,
	}
	return profile, nil
}

// BanChatMember permanently removes a user from a group, supergroup, or channel.
func (c *Client) BanChatMember(ctx context.Context, chatID, userID int64) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if userID <= 0 {
		return fmt.Errorf("Telegram user ID must be positive")
	}

	var banned bool
	if err := c.call(ctx, "banChatMember", struct {
		ChatID int64 `json:"chat_id"`
		UserID int64 `json:"user_id"`
	}{ChatID: chatID, UserID: userID}, &banned); err != nil {
		return fmt.Errorf("ban Telegram chat member: %w", err)
	}
	if !banned {
		return fmt.Errorf("ban Telegram chat member: Telegram returned false")
	}
	return nil
}

// UnbanChatMember reverses a previous ban without forcing the user to rejoin.
func (c *Client) UnbanChatMember(ctx context.Context, chatID, userID int64) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if userID <= 0 {
		return fmt.Errorf("Telegram user ID must be positive")
	}
	var unbanned bool
	if err := c.call(ctx, "unbanChatMember", struct {
		ChatID       int64 `json:"chat_id"`
		UserID       int64 `json:"user_id"`
		OnlyIfBanned bool  `json:"only_if_banned"`
	}{ChatID: chatID, UserID: userID, OnlyIfBanned: true}, &unbanned); err != nil {
		return fmt.Errorf("unban Telegram chat member: %w", err)
	}
	if !unbanned {
		return fmt.Errorf("unban Telegram chat member: Telegram returned false")
	}
	return nil
}

// DeleteMessage deletes one Telegram message.
func (c *Client) DeleteMessage(ctx context.Context, chatID, messageID int64) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if messageID <= 0 {
		return fmt.Errorf("Telegram message ID must be positive")
	}
	var deleted bool
	if err := c.call(ctx, "deleteMessage", struct {
		ChatID    int64 `json:"chat_id"`
		MessageID int64 `json:"message_id"`
	}{ChatID: chatID, MessageID: messageID}, &deleted); err != nil {
		return fmt.Errorf("delete Telegram message: %w", err)
	}
	if !deleted {
		return fmt.Errorf("delete Telegram message: Telegram returned false")
	}
	return nil
}

// DeleteMessageReaction removes the specified user's reaction from a message.
func (c *Client) DeleteMessageReaction(ctx context.Context, chatID, messageID, userID int64) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if messageID <= 0 {
		return fmt.Errorf("Telegram message ID must be positive")
	}
	if userID <= 0 {
		return fmt.Errorf("Telegram user ID must be positive")
	}
	var deleted bool
	if err := c.call(ctx, "deleteMessageReaction", struct {
		ChatID    int64 `json:"chat_id"`
		MessageID int64 `json:"message_id"`
		UserID    int64 `json:"user_id"`
	}{ChatID: chatID, MessageID: messageID, UserID: userID}, &deleted); err != nil {
		return fmt.Errorf("delete Telegram message reaction: %w", err)
	}
	if !deleted {
		return fmt.Errorf("delete Telegram message reaction: Telegram returned false")
	}
	return nil
}

// RestrictChatMember mutes a user until the supplied Unix timestamp.
func (c *Client) RestrictChatMember(ctx context.Context, chatID, userID, untilDate int64) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if userID <= 0 {
		return fmt.Errorf("Telegram user ID must be positive")
	}
	if untilDate <= time.Now().Unix() {
		return fmt.Errorf("Telegram mute expiration must be in the future")
	}
	var restricted bool
	if err := c.call(ctx, "restrictChatMember", struct {
		ChatID      int64 `json:"chat_id"`
		UserID      int64 `json:"user_id"`
		UntilDate   int64 `json:"until_date"`
		Permissions struct {
			CanSendMessages bool `json:"can_send_messages"`
		} `json:"permissions"`
	}{ChatID: chatID, UserID: userID, UntilDate: untilDate}, &restricted); err != nil {
		return fmt.Errorf("restrict Telegram chat member: %w", err)
	}
	if !restricted {
		return fmt.Errorf("restrict Telegram chat member: Telegram returned false")
	}
	return nil
}

// SendMessage sends a plain-text bot response without parse-mode injection.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if strings.TrimSpace(text) == "" || len([]rune(text)) > 4096 {
		return fmt.Errorf("Telegram message text must contain 1 to 4096 characters")
	}
	var sent message
	if err := c.call(ctx, "sendMessage", struct {
		ChatID int64  `json:"chat_id"`
		Text   string `json:"text"`
	}{ChatID: chatID, Text: text}, &sent); err != nil {
		return fmt.Errorf("send Telegram message: %w", err)
	}
	return nil
}

// GetBotUsername returns the authenticated bot username used in Telegram deep links.
func (c *Client) GetBotUsername(ctx context.Context) (string, error) {
	var bot struct {
		Username string `json:"username"`
	}
	if err := c.call(ctx, "getMe", struct{}{}, &bot); err != nil {
		return "", fmt.Errorf("get Telegram bot identity: %w", err)
	}
	if strings.TrimSpace(bot.Username) == "" {
		return "", fmt.Errorf("get Telegram bot identity: invalid username")
	}
	return bot.Username, nil
}

// SendMessageWithURLButton sends plain text with one HTTPS inline URL button.
func (c *Client) SendMessageWithURLButton(
	ctx context.Context,
	chatID int64,
	text string,
	buttonText string,
	buttonURL string,
) error {
	if chatID == 0 {
		return fmt.Errorf("Telegram chat ID must not be zero")
	}
	if strings.TrimSpace(text) == "" || len([]rune(text)) > 4096 {
		return fmt.Errorf("Telegram message text must contain 1 to 4096 characters")
	}
	if strings.TrimSpace(buttonText) == "" || len([]rune(buttonText)) > 64 {
		return fmt.Errorf("Telegram button text must contain 1 to 64 characters")
	}
	parsedURL, err := url.Parse(buttonURL)
	if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.User != nil {
		return fmt.Errorf("Telegram button URL must be an absolute HTTPS URL")
	}
	var sent message
	request := struct {
		ChatID      int64  `json:"chat_id"`
		Text        string `json:"text"`
		ReplyMarkup struct {
			InlineKeyboard [][]struct {
				Text string `json:"text"`
				URL  string `json:"url"`
			} `json:"inline_keyboard"`
		} `json:"reply_markup"`
	}{ChatID: chatID, Text: text}
	request.ReplyMarkup.InlineKeyboard = [][]struct {
		Text string `json:"text"`
		URL  string `json:"url"`
	}{{{Text: buttonText, URL: buttonURL}}}
	if err := c.call(ctx, "sendMessage", request, &sent); err != nil {
		return fmt.Errorf("send Telegram message with URL button: %w", err)
	}
	return nil
}

// SetWebhook registers all update types consumed by AntiSpamBee, including
// reactions which Telegram excludes from the default subscription.
func (c *Client) SetWebhook(ctx context.Context, webhookURL, secret string) error {
	parsed, err := url.Parse(webhookURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("Telegram webhook URL must be an absolute HTTPS URL")
	}
	if !validWebhookSecret(secret) {
		return fmt.Errorf("Telegram webhook secret must use 1-256 A-Z, a-z, 0-9, underscore, or hyphen characters")
	}
	var configured bool
	if err := c.call(ctx, "setWebhook", struct {
		URL            string   `json:"url"`
		SecretToken    string   `json:"secret_token"`
		AllowedUpdates []string `json:"allowed_updates"`
	}{
		URL: webhookURL, SecretToken: secret,
		AllowedUpdates: []string{
			"message", "edited_message", "channel_post", "edited_channel_post",
			"callback_query", "message_reaction",
		},
	}, &configured); err != nil {
		return fmt.Errorf("set Telegram webhook: %w", err)
	}
	if !configured {
		return fmt.Errorf("set Telegram webhook: Telegram returned false")
	}
	return nil
}

func validWebhookSecret(secret string) bool {
	if len(secret) == 0 || len(secret) > 256 {
		return false
	}
	for _, r := range secret {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// GetChatMemberStatus returns member, administrator, creator, restricted,
// left, or kicked as reported by Telegram.
func (c *Client) GetChatMemberStatus(ctx context.Context, chatID, userID int64) (string, error) {
	if chatID == 0 {
		return "", fmt.Errorf("Telegram chat ID must not be zero")
	}
	if userID <= 0 {
		return "", fmt.Errorf("Telegram user ID must be positive")
	}
	var member struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, "getChatMember", struct {
		ChatID int64 `json:"chat_id"`
		UserID int64 `json:"user_id"`
	}{ChatID: chatID, UserID: userID}, &member); err != nil {
		return "", fmt.Errorf("get Telegram chat member: %w", err)
	}
	if member.Status == "" {
		return "", fmt.Errorf("get Telegram chat member: empty status")
	}
	return member.Status, nil
}

func (c *Client) call(ctx context.Context, method string, payload, result any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/bot"+c.token+"/"+method,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()

	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   int             `json:"error_code"`
		Description string          `json:"description"`
		Parameters  struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 || !envelope.OK {
		return &APIError{
			ErrorCode:   envelope.ErrorCode,
			Description: envelope.Description,
			RetryAfter:  time.Duration(envelope.Parameters.RetryAfter) * time.Second,
		}
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("decode result: %w", err)
	}
	return nil
}

type chat struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Username string `json:"username"`
}

type chatFullInfo struct {
	chat
	Bio          string `json:"bio"`
	Description  string `json:"description"`
	PersonalChat *chat  `json:"personal_chat"`
}

type message struct {
	MessageID int64  `json:"message_id"`
	Text      string `json:"text"`
	Caption   string `json:"caption"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
