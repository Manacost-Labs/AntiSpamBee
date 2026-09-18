package main

import (
	"testing"
	"time"
)

func TestLoadConfigUsesSafeDefaults(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":       "postgres://antispambee:secret@localhost:5432/antispambee",
		"TELEGRAM_BOT_TOKEN": "123456:secret",
		"OPENROUTER_API_KEY": "openrouter-secret",
	}

	config, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if config.NATSURL != "nats://127.0.0.1:4222" {
		t.Errorf("NATS URL = %q", config.NATSURL)
	}
	if config.Stream != "TELEGRAM_EVENTS" || config.Subject != "telegram.events" {
		t.Errorf("stream = %q, subject = %q", config.Stream, config.Subject)
	}
	if config.Consumer != "moderation-worker" {
		t.Errorf("consumer = %q", config.Consumer)
	}
	if config.RetryDelay != 5*time.Second {
		t.Errorf("retry delay = %s", config.RetryDelay)
	}
	if config.OpenRouterBaseURL != "https://openrouter.ai" {
		t.Errorf("OpenRouter base URL = %q", config.OpenRouterBaseURL)
	}
	if config.OpenRouterModel != "~typesafe/jev-latest" {
		t.Errorf("OpenRouter model = %q", config.OpenRouterModel)
	}
	if config.HTTPAddress != ":8082" {
		t.Errorf("HTTP address = %q", config.HTTPAddress)
	}
	if config.OCREnabled {
		t.Fatal("OCR must be disabled by default")
	}
	if config.OCRMaxBytes != 8<<20 || config.OCRTimeout != 12*time.Second || config.OCRLanguage != "rus+eng" {
		t.Fatalf("OCR defaults = %d/%s/%q", config.OCRMaxBytes, config.OCRTimeout, config.OCRLanguage)
	}
}

func TestLoadConfigEnablesBoundedOCR(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":       "postgres://antispambee:secret@localhost:5432/antispambee",
		"TELEGRAM_BOT_TOKEN": "123456:secret",
		"OCR_ENABLED":        "true",
		"OCR_MAX_BYTES":      "4194304",
		"OCR_TIMEOUT":        "8s",
		"OCR_LANGUAGE":       "rus+eng",
	}
	config, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if !config.OCREnabled || config.OCRMaxBytes != 4<<20 || config.OCRTimeout != 8*time.Second {
		t.Fatalf("OCR config = %#v", config)
	}
}

func TestLoadConfigRejectsInvalidOCRSettings(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":       "postgres://antispambee:secret@localhost:5432/antispambee",
		"TELEGRAM_BOT_TOKEN": "123456:secret",
		"OCR_ENABLED":        "sometimes",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err == nil {
		t.Fatal("loadConfig() error = nil, want invalid OCR setting error")
	}
}

func TestLoadConfigRequiresDatabaseURL(t *testing.T) {
	_, err := loadConfig(func(string) string { return "" })
	if err == nil {
		t.Fatal("loadConfig() succeeded without DATABASE_URL")
	}
}

func TestLoadConfigRequiresTelegramBotToken(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL": "postgres://antispambee:secret@localhost:5432/antispambee",
	}

	_, err := loadConfig(func(key string) string { return values[key] })
	if err == nil {
		t.Fatal("loadConfig() succeeded without TELEGRAM_BOT_TOKEN")
	}
}

func TestLoadConfigKeepsOpenRouterDisabledWithoutAPIKey(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":       "postgres://antispambee:secret@localhost:5432/antispambee",
		"TELEGRAM_BOT_TOKEN": "123456:secret",
	}

	config, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if config.OpenRouterAPIKey != "" {
		t.Fatal("OpenRouter should be disabled without OPENROUTER_API_KEY")
	}
}
