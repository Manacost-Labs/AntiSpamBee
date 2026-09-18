package main

import "fmt"

type config struct {
	TelegramBotToken string
	WebhookURL       string
	WebhookSecret    string
}

func loadConfig(getenv func(string) string) (config, error) {
	loaded := config{
		TelegramBotToken: getenv("TELEGRAM_BOT_TOKEN"),
		WebhookURL:       getenv("TELEGRAM_WEBHOOK_URL"),
		WebhookSecret:    getenv("TELEGRAM_WEBHOOK_SECRET"),
	}
	if loaded.TelegramBotToken == "" || loaded.WebhookURL == "" || loaded.WebhookSecret == "" {
		return config{}, fmt.Errorf("TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_URL, and TELEGRAM_WEBHOOK_SECRET are required")
	}
	return loaded, nil
}
