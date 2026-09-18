package main

import (
	"fmt"
	"strconv"
	"time"
)

type config struct {
	DatabaseURL       string
	TelegramBotToken  string
	OpenRouterAPIKey  string
	OpenRouterBaseURL string
	OpenRouterModel   string
	NATSURL           string
	Stream            string
	Subject           string
	Consumer          string
	RetryDelay        time.Duration
	ModeratorChatID   int64
	HTTPAddress       string
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
	var moderatorChatID int64
	if raw := getenv("MODERATOR_CHAT_ID"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed == 0 {
			return config{}, fmt.Errorf("MODERATOR_CHAT_ID must be a non-zero integer")
		}
		moderatorChatID = parsed
	}

	return config{
		DatabaseURL:       databaseURL,
		TelegramBotToken:  botToken,
		OpenRouterAPIKey:  openRouterAPIKey,
		OpenRouterBaseURL: valueOrDefault(getenv("OPENROUTER_BASE_URL"), "https://openrouter.ai"),
		OpenRouterModel:   valueOrDefault(getenv("OPENROUTER_MODEL"), "~typesafe/jev-latest"),
		NATSURL:           valueOrDefault(getenv("NATS_URL"), "nats://127.0.0.1:4222"),
		Stream:            valueOrDefault(getenv("NATS_STREAM"), "TELEGRAM_EVENTS"),
		Subject:           valueOrDefault(getenv("NATS_SUBJECT"), "telegram.events"),
		Consumer:          valueOrDefault(getenv("NATS_CONSUMER"), "moderation-worker"),
		RetryDelay:        5 * time.Second,
		ModeratorChatID:   moderatorChatID,
		HTTPAddress:       valueOrDefault(getenv("MODERATION_WORKER_HTTP_ADDR"), ":8082"),
	}, nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
