package main

import "testing"

func TestLoadConfigUsesSafeDefaults(t *testing.T) {
	environment := map[string]string{
		"TELEGRAM_BOT_ID":         "123456",
		"TELEGRAM_WEBHOOK_SECRET": "secret",
		"TENANT_ID":               "11111111-1111-4111-8111-111111111111",
	}

	config, err := loadConfig(func(key string) string { return environment[key] })
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if config.HTTPAddress != ":8080" {
		t.Fatalf("HTTPAddress = %q, want :8080", config.HTTPAddress)
	}
	if config.NATSURL != "nats://127.0.0.1:4222" {
		t.Fatalf("NATSURL = %q", config.NATSURL)
	}
	if config.Stream != "TELEGRAM_EVENTS" || config.Subject != "telegram.events" {
		t.Fatalf("stream target = %q/%q", config.Stream, config.Subject)
	}
}

func TestLoadConfigRejectsMissingCredentials(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
	}{
		{name: "missing bot ID", environment: map[string]string{"TELEGRAM_WEBHOOK_SECRET": "secret"}},
		{name: "invalid bot ID", environment: map[string]string{"TELEGRAM_BOT_ID": "bot", "TELEGRAM_WEBHOOK_SECRET": "secret", "TENANT_ID": "11111111-1111-4111-8111-111111111111"}},
		{name: "missing webhook secret", environment: map[string]string{"TELEGRAM_BOT_ID": "123456", "TENANT_ID": "11111111-1111-4111-8111-111111111111"}},
		{name: "missing tenant ID", environment: map[string]string{"TELEGRAM_BOT_ID": "123456", "TELEGRAM_WEBHOOK_SECRET": "secret"}},
		{name: "invalid tenant ID", environment: map[string]string{"TELEGRAM_BOT_ID": "123456", "TELEGRAM_WEBHOOK_SECRET": "secret", "TENANT_ID": "tenant"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := loadConfig(func(key string) string { return tt.environment[key] }); err == nil {
				t.Fatal("loadConfig() error = nil, want configuration error")
			}
		})
	}
}
