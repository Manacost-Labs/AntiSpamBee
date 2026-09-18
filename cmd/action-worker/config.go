package main

import (
	"fmt"
	"time"
)

type config struct {
	DatabaseURL      string
	TelegramBotToken string
	WorkerID         string
	HTTPAddress      string
	PollInterval     time.Duration
}

func loadConfig(getenv func(string) string) (config, error) {
	databaseURL := getenv("DATABASE_URL")
	if databaseURL == "" {
		return config{}, fmt.Errorf("DATABASE_URL is required")
	}
	token := getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		return config{}, fmt.Errorf("TELEGRAM_BOT_TOKEN is required")
	}
	workerID := getenv("ACTION_WORKER_ID")
	if workerID == "" {
		workerID = "action-worker"
	}
	httpAddress := getenv("ACTION_WORKER_HTTP_ADDR")
	if httpAddress == "" {
		httpAddress = ":8081"
	}
	pollInterval := 250 * time.Millisecond
	if raw := getenv("ACTION_WORKER_POLL_INTERVAL"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			return config{}, fmt.Errorf("ACTION_WORKER_POLL_INTERVAL must be a positive duration")
		}
		pollInterval = parsed
	}
	return config{
		DatabaseURL:      databaseURL,
		TelegramBotToken: token,
		WorkerID:         workerID,
		HTTPAddress:      httpAddress,
		PollInterval:     pollInterval,
	}, nil
}
