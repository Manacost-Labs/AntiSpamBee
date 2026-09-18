package telegramapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
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
	Text    string `json:"text"`
	Caption string `json:"caption"`
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
