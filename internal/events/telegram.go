package events

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
)

var telegramNamespace = [16]byte{
	0xf9, 0xb4, 0xfb, 0x63,
	0xc8, 0x29,
	0x5b, 0xcb,
	0xa7, 0x6f,
	0xf6, 0x37, 0xe8, 0xcc, 0x64, 0x3b,
}

// TelegramIdentity is the stable identity of one Telegram update.
type TelegramIdentity struct {
	SourceKey string
	EventID   string
}

// TelegramUpdate is the versioned event persisted before a webhook is acknowledged.
type TelegramUpdate struct {
	SchemaVersion string          `json:"schema_version"`
	TenantID      string          `json:"tenant_id"`
	EventID       string          `json:"event_id"`
	SourceKey     string          `json:"source_key"`
	BotID         int64           `json:"bot_id"`
	UpdateID      int64           `json:"update_id"`
	Payload       json.RawMessage `json:"payload"`
}

// NewTelegramIdentity creates the source key used by JetStream deduplication
// and its deterministic UUIDv5 event identifier.
func NewTelegramIdentity(botID, updateID int64) (TelegramIdentity, error) {
	if botID <= 0 {
		return TelegramIdentity{}, fmt.Errorf("bot ID must be positive")
	}
	if updateID <= 0 {
		return TelegramIdentity{}, fmt.Errorf("update ID must be positive")
	}

	sourceKey := fmt.Sprintf("telegram:%d:%d", botID, updateID)

	return TelegramIdentity{
		SourceKey: sourceKey,
		EventID:   uuidV5(telegramNamespace, sourceKey),
	}, nil
}

func uuidV5(namespace [16]byte, name string) string {
	hash := sha1.New()
	_, _ = hash.Write(namespace[:])
	_, _ = hash.Write([]byte(name))
	sum := hash.Sum(nil)

	var id [16]byte
	copy(id[:], sum)
	id[6] = (id[6] & 0x0f) | 0x50
	id[8] = (id[8] & 0x3f) | 0x80

	return fmt.Sprintf(
		"%x-%x-%x-%x-%x",
		id[0:4],
		id[4:6],
		id[6:8],
		id[8:10],
		id[10:16],
	)
}
