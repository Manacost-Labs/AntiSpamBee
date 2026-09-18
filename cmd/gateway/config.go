package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

type config struct {
	HTTPAddress   string
	TenantID      string
	BotID         int64
	WebhookSecret string
	NATSURL       string
	Stream        string
	Subject       string
}

func loadConfig(getenv func(string) string) (config, error) {
	botID, err := strconv.ParseInt(getenv("TELEGRAM_BOT_ID"), 10, 64)
	if err != nil || botID <= 0 {
		return config{}, fmt.Errorf("TELEGRAM_BOT_ID must be a positive integer")
	}
	secret := getenv("TELEGRAM_WEBHOOK_SECRET")
	if secret == "" {
		return config{}, fmt.Errorf("TELEGRAM_WEBHOOK_SECRET is required")
	}
	tenantID := getenv("TENANT_ID")
	if !validUUID(tenantID) {
		return config{}, fmt.Errorf("TENANT_ID must be a UUID")
	}

	return config{
		HTTPAddress:   valueOrDefault(getenv("HTTP_ADDR"), ":8080"),
		TenantID:      tenantID,
		BotID:         botID,
		WebhookSecret: secret,
		NATSURL:       valueOrDefault(getenv("NATS_URL"), "nats://127.0.0.1:4222"),
		Stream:        valueOrDefault(getenv("NATS_STREAM"), "TELEGRAM_EVENTS"),
		Subject:       valueOrDefault(getenv("NATS_SUBJECT"), "telegram.events"),
	}, nil
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
