package main

import (
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	values := map[string]string{
		"DATABASE_URL":       "postgres://test",
		"TELEGRAM_BOT_TOKEN": "secret",
	}
	config, err := loadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.WorkerID != "action-worker" || config.HTTPAddress != ":8081" || config.PollInterval != 250*time.Millisecond {
		t.Fatalf("defaults = %#v", config)
	}
}

func TestLoadConfigRequiresCredentials(t *testing.T) {
	if _, err := loadConfig(func(string) string { return "" }); err == nil {
		t.Fatal("loadConfig() succeeded without credentials")
	}
}
