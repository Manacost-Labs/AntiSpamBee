package events

import "testing"

func TestNewTelegramIdentityCreatesStableSourceIdentity(t *testing.T) {
	identity, err := NewTelegramIdentity(123456, 789)
	if err != nil {
		t.Fatalf("NewTelegramIdentity() error = %v", err)
	}

	if identity.SourceKey != "telegram:123456:789" {
		t.Fatalf("SourceKey = %q, want %q", identity.SourceKey, "telegram:123456:789")
	}
	if identity.EventID != "82373d0f-5740-5f07-b4e8-02c2f4edd824" {
		t.Fatalf("EventID = %q, want deterministic UUIDv5", identity.EventID)
	}
}

func TestNewTelegramIdentityChangesWhenUpdateChanges(t *testing.T) {
	first, err := NewTelegramIdentity(123456, 789)
	if err != nil {
		t.Fatalf("NewTelegramIdentity() first error = %v", err)
	}
	second, err := NewTelegramIdentity(123456, 790)
	if err != nil {
		t.Fatalf("NewTelegramIdentity() second error = %v", err)
	}

	if first.EventID == second.EventID {
		t.Fatal("EventID must change when update_id changes")
	}
}

func TestNewTelegramIdentityRejectsInvalidIdentifiers(t *testing.T) {
	tests := []struct {
		name     string
		botID    int64
		updateID int64
	}{
		{name: "missing bot ID", botID: 0, updateID: 789},
		{name: "negative bot ID", botID: -1, updateID: 789},
		{name: "missing update ID", botID: 123456, updateID: 0},
		{name: "negative update ID", botID: 123456, updateID: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTelegramIdentity(tt.botID, tt.updateID); err == nil {
				t.Fatal("NewTelegramIdentity() error = nil, want validation error")
			}
		})
	}
}
