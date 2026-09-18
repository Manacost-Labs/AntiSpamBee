package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"antispambee/internal/telegramapi"
)

func main() {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	client, err := telegramapi.NewClient(telegramapi.ClientConfig{Token: config.TelegramBotToken})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.SetWebhook(ctx, config.WebhookURL, config.WebhookSecret); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Telegram webhook configured")
}
