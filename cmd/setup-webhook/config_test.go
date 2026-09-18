package main

import "testing"

func TestLoadConfigRequiresAllWebhookValues(t *testing.T) {
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("loadConfig() succeeded without configuration")
	}
	values := map[string]string{
		"TELEGRAM_BOT_TOKEN": "token", "TELEGRAM_WEBHOOK_URL": "https://example.test/telegram/webhook",
		"TELEGRAM_WEBHOOK_SECRET": "secret",
	}
	if _, err := loadConfig(func(key string) string { return values[key] }); err != nil {
		t.Fatal(err)
	}
}
