package main

import (
	"fmt"
	"strconv"
	"time"
)

type config struct {
	DatabaseURL                string
	TelegramBotToken           string
	OpenRouterAPIKey           string
	OpenRouterBaseURL          string
	OpenRouterModel            string
	OpenRouterContentModel     string
	OpenRouterContentChatID    int64
	AdvertisingAutobanChatID   int64
	OpenRouterBanModel         string
	ModerationOperationsChatID int64
	OCREnabled                 bool
	OCRExecutable              string
	OCRLanguage                string
	OCRMaxBytes                int64
	OCRTimeout                 time.Duration
	NATSURL                    string
	Stream                     string
	Subject                    string
	Consumer                   string
	RetryDelay                 time.Duration
	ModeratorChatID            int64
	HTTPAddress                string
}

func loadConfig(getenv func(string) string) (config, error) {
	databaseURL := getenv("DATABASE_URL")
	if databaseURL == "" {
		return config{}, fmt.Errorf("DATABASE_URL is required")
	}
	botToken := getenv("TELEGRAM_BOT_TOKEN")
	if botToken == "" {
		return config{}, fmt.Errorf("TELEGRAM_BOT_TOKEN is required")
	}
	openRouterAPIKey := getenv("OPENROUTER_API_KEY")
	openRouterContentModel := getenv("OPENROUTER_CONTENT_MODEL")
	if openRouterContentModel != "" && openRouterAPIKey == "" {
		return config{}, fmt.Errorf("OPENROUTER_API_KEY is required for OPENROUTER_CONTENT_MODEL")
	}
	var openRouterContentChatID int64
	if chatID := getenv("OPENROUTER_CONTENT_CHAT_ID"); chatID != "" {
		parsed, err := strconv.ParseInt(chatID, 10, 64)
		if err != nil || parsed >= 0 || openRouterContentModel == "" {
			return config{}, fmt.Errorf("OPENROUTER_CONTENT_CHAT_ID requires a negative Telegram chat ID and OPENROUTER_CONTENT_MODEL")
		}
		openRouterContentChatID = parsed
	}
	var advertisingAutobanChatID int64
	var moderationOperationsChatID int64
	if value := getenv("MODERATION_OPERATIONS_CHAT_ID"); value != "" {
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed >= 0 {
			return config{}, fmt.Errorf("MODERATION_OPERATIONS_CHAT_ID must be a negative Telegram chat ID")
		}
		moderationOperationsChatID = parsed
	}
	openRouterBanModel := valueOrDefault(getenv("OPENROUTER_BAN_MODEL"), "openai/gpt-4.1")
	if chatID := getenv("AUTOBAN_ADVERTISING_CHAT_ID"); chatID != "" {
		parsed, err := strconv.ParseInt(chatID, 10, 64)
		if err != nil || parsed >= 0 || openRouterContentModel == "" || (openRouterContentChatID != 0 && parsed != openRouterContentChatID) {
			return config{}, fmt.Errorf("AUTOBAN_ADVERTISING_CHAT_ID requires a group with multimodal classification")
		}
		if openRouterBanModel == openRouterContentModel {
			return config{}, fmt.Errorf("OPENROUTER_BAN_MODEL must differ from OPENROUTER_CONTENT_MODEL")
		}
		advertisingAutobanChatID = parsed
	}
	ocrEnabled := false
	if raw := getenv("OCR_ENABLED"); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return config{}, fmt.Errorf("OCR_ENABLED must be true or false")
		}
		ocrEnabled = parsed
	}
	ocrMaxBytes := int64(8 << 20)
	if raw := getenv("OCR_MAX_BYTES"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 || parsed > 20<<20 {
			return config{}, fmt.Errorf("OCR_MAX_BYTES must be between 1 and 20971520")
		}
		ocrMaxBytes = parsed
	}
	ocrTimeout := 12 * time.Second
	if raw := getenv("OCR_TIMEOUT"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 || parsed > time.Minute {
			return config{}, fmt.Errorf("OCR_TIMEOUT must be between 1ns and 1m")
		}
		ocrTimeout = parsed
	}
	var moderatorChatID int64
	if raw := getenv("MODERATOR_CHAT_ID"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed == 0 {
			return config{}, fmt.Errorf("MODERATOR_CHAT_ID must be a non-zero integer")
		}
		moderatorChatID = parsed
	}

	return config{
		DatabaseURL:                databaseURL,
		TelegramBotToken:           botToken,
		OpenRouterAPIKey:           openRouterAPIKey,
		OpenRouterBaseURL:          valueOrDefault(getenv("OPENROUTER_BASE_URL"), "https://openrouter.ai"),
		OpenRouterModel:            valueOrDefault(getenv("OPENROUTER_MODEL"), "~typesafe/jev-latest"),
		OpenRouterContentModel:     openRouterContentModel,
		OpenRouterContentChatID:    openRouterContentChatID,
		AdvertisingAutobanChatID:   advertisingAutobanChatID,
		OpenRouterBanModel:         openRouterBanModel,
		ModerationOperationsChatID: moderationOperationsChatID,
		OCREnabled:                 ocrEnabled,
		OCRExecutable:              valueOrDefault(getenv("OCR_EXECUTABLE"), "tesseract"),
		OCRLanguage:                valueOrDefault(getenv("OCR_LANGUAGE"), "rus+eng"),
		OCRMaxBytes:                ocrMaxBytes,
		OCRTimeout:                 ocrTimeout,
		NATSURL:                    valueOrDefault(getenv("NATS_URL"), "nats://127.0.0.1:4222"),
		Stream:                     valueOrDefault(getenv("NATS_STREAM"), "TELEGRAM_EVENTS"),
		Subject:                    valueOrDefault(getenv("NATS_SUBJECT"), "telegram.events"),
		Consumer:                   valueOrDefault(getenv("NATS_CONSUMER"), "moderation-worker"),
		RetryDelay:                 5 * time.Second,
		ModeratorChatID:            moderatorChatID,
		HTTPAddress:                valueOrDefault(getenv("MODERATION_WORKER_HTTP_ADDR"), ":8082"),
	}, nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
