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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.SetWebhook(ctx, config.WebhookURL, config.WebhookSecret); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := client.SetMyCommands(ctx, defaultCommands()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("Telegram webhook and command menu configured")
}

func defaultCommands() []telegramapi.BotCommand {
	return []telegramapi.BotCommand{
		{Command: "start", Description: "Открыть меню и добавить бота в группу"},
		{Command: "help", Description: "Справочник по командам"},
		{Command: "report", Description: "Пожаловаться на сообщение"},
		{Command: "status", Description: "Показать режим защиты"},
		{Command: "link", Description: "Привязать группу к личному кабинету"},
		{Command: "protection", Description: "Изменить режим защиты"},
		{Command: "allow", Description: "Добавить пользователя в исключения"},
		{Command: "unallow", Description: "Убрать пользователя из исключений"},
		{Command: "warn", Description: "Предупредить пользователя"},
		{Command: "mute", Description: "Ограничить пользователя на час"},
		{Command: "ban", Description: "Заблокировать пользователя"},
		{Command: "unban", Description: "Снять блокировку по USER_ID"},
	}
}
