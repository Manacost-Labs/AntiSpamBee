package postgresstore

import (
	"testing"

	"antispambee/internal/moderation"
)

func TestValidateCommunityPolicyLookupAllowsAnonymousSenderChat(t *testing.T) {
	t.Parallel()

	if err := validateCommunityPolicyLookup("tenant", -100777, 0); err != nil {
		t.Fatalf("validateCommunityPolicyLookup() error = %v, want nil for sender_chat", err)
	}
}

func TestValidateCommunityPolicyLookupRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenantID string
		chatID   int64
		userID   int64
	}{
		{name: "missing tenant", chatID: -100777, userID: 42},
		{name: "missing chat", tenantID: "tenant", userID: 42},
		{name: "negative user", tenantID: "tenant", chatID: -100777, userID: -1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateCommunityPolicyLookup(test.tenantID, test.chatID, test.userID); err == nil {
				t.Fatal("validateCommunityPolicyLookup() error = nil, want validation error")
			}
		})
	}
}

func TestNormalizeInputFeaturesProvidesDatabaseSafeDefaults(t *testing.T) {
	got := normalizeInputFeatures(moderation.InputFeatures{})

	if got.UpdateKind != "unknown" {
		t.Fatalf("UpdateKind = %q, want unknown", got.UpdateKind)
	}
	if got.MediaTypes == nil || len(got.MediaTypes) != 0 {
		t.Fatalf("MediaTypes = %#v, want non-nil empty slice", got.MediaTypes)
	}
}
