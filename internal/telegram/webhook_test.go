package telegram

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"antispambee/internal/events"
)

type recordingPublisher struct {
	events []events.TelegramUpdate
	err    error
}

func (p *recordingPublisher) PublishTelegramUpdate(_ context.Context, event events.TelegramUpdate) error {
	p.events = append(p.events, event)
	return p.err
}

func TestWebhookPublishesValidatedUpdateBeforeAcknowledging(t *testing.T) {
	publisher := &recordingPublisher{}
	handler, err := NewWebhookHandler(WebhookConfig{TenantID: "11111111-1111-4111-8111-111111111111", BotID: 123456, Secret: "telegram-secret"}, publisher)
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(`{"update_id":789,"message":{"text":"hello"}}`))
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "telegram-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if len(publisher.events) != 1 {
		t.Fatalf("published events = %d, want 1", len(publisher.events))
	}
	if publisher.events[0].SourceKey != "telegram:123456:789" {
		t.Fatalf("SourceKey = %q", publisher.events[0].SourceKey)
	}
	if publisher.events[0].TenantID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("TenantID = %q", publisher.events[0].TenantID)
	}
	if publisher.events[0].EventID != "82373d0f-5740-5f07-b4e8-02c2f4edd824" {
		t.Fatalf("EventID = %q", publisher.events[0].EventID)
	}
}

func TestWebhookRejectsInvalidSecretWithoutPublishing(t *testing.T) {
	publisher := &recordingPublisher{}
	handler, err := NewWebhookHandler(WebhookConfig{TenantID: "11111111-1111-4111-8111-111111111111", BotID: 123456, Secret: "telegram-secret"}, publisher)
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(`{"update_id":789}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if len(publisher.events) != 0 {
		t.Fatalf("published events = %d, want 0", len(publisher.events))
	}
}

func TestWebhookReturnsServiceUnavailableWhenPublishFails(t *testing.T) {
	publisher := &recordingPublisher{err: errors.New("NATS unavailable")}
	handler, err := NewWebhookHandler(WebhookConfig{TenantID: "11111111-1111-4111-8111-111111111111", BotID: 123456, Secret: "telegram-secret"}, publisher)
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(`{"update_id":789}`))
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "telegram-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestWebhookRejectsMalformedUpdate(t *testing.T) {
	publisher := &recordingPublisher{}
	handler, err := NewWebhookHandler(WebhookConfig{TenantID: "11111111-1111-4111-8111-111111111111", BotID: 123456, Secret: "telegram-secret"}, publisher)
	if err != nil {
		t.Fatalf("NewWebhookHandler() error = %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/telegram/webhook", strings.NewReader(`{"update_id":`))
	request.Header.Set("X-Telegram-Bot-Api-Secret-Token", "telegram-secret")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
	if len(publisher.events) != 0 {
		t.Fatalf("published events = %d, want 0", len(publisher.events))
	}
}
