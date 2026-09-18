package telegram

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"antispambee/internal/events"
)

const (
	telegramSecretHeader = "X-Telegram-Bot-Api-Secret-Token"
	maxWebhookBodyBytes  = 1 << 20
)

type updatePublisher interface {
	PublishTelegramUpdate(context.Context, events.TelegramUpdate) error
}

// WebhookConfig identifies the tenant and Telegram bot owning a webhook.
type WebhookConfig struct {
	TenantID string
	BotID    int64
	Secret   string
}

// WebhookHandler validates and durably publishes Telegram updates.
type WebhookHandler struct {
	tenantID  string
	botID     int64
	secret    string
	publisher updatePublisher
}

// NewWebhookHandler validates immutable webhook configuration at startup.
func NewWebhookHandler(config WebhookConfig, publisher updatePublisher) (*WebhookHandler, error) {
	if config.TenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	if config.BotID <= 0 {
		return nil, fmt.Errorf("bot ID must be positive")
	}
	if config.Secret == "" {
		return nil, fmt.Errorf("webhook secret is required")
	}
	if publisher == nil {
		return nil, fmt.Errorf("update publisher is required")
	}

	return &WebhookHandler{
		tenantID:  config.TenantID,
		botID:     config.BotID,
		secret:    config.Secret,
		publisher: publisher,
	}, nil
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !equalSecret(r.Header.Get(telegramSecretHeader), h.secret) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodyBytes)
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	var update struct {
		UpdateID int64 `json:"update_id"`
	}
	if err := json.Unmarshal(payload, &update); err != nil || update.UpdateID <= 0 {
		http.Error(w, "invalid Telegram update", http.StatusBadRequest)
		return
	}

	identity, err := events.NewTelegramIdentity(h.botID, update.UpdateID)
	if err != nil {
		http.Error(w, "invalid Telegram update", http.StatusBadRequest)
		return
	}
	event := events.TelegramUpdate{
		SchemaVersion: "1",
		TenantID:      h.tenantID,
		EventID:       identity.EventID,
		SourceKey:     identity.SourceKey,
		BotID:         h.botID,
		UpdateID:      update.UpdateID,
		Payload:       payload,
	}
	if err := h.publisher.PublishTelegramUpdate(r.Context(), event); err != nil {
		http.Error(w, "event persistence unavailable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func equalSecret(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
