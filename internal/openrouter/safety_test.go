package openrouter

import (
	"antispambee/internal/detection"
	"testing"
)

func TestSemanticStateNeverUsesProfileAsMessageEvidence(t *testing.T) {
	profile := detection.Profile{Username: "casino", Bio: "bonus deposit", PersonalChannel: &detection.PersonalChannel{Title: "Casino"}}
	state, coverage := semanticState(detection.SemanticAdContent{Profile: profile})
	if len(state) != 0 || coverage != 0 {
		t.Fatalf("profile became evidence: %v %v", state, coverage)
	}
	state, _ = semanticState(detection.SemanticAdContent{Profile: profile, Message: detection.MessageContent{Text: "Привет"}})
	if len(state) != 2 || state["message_text"] != "Привет" {
		t.Fatalf("profile leaked into message analysis: %v", state)
	}
}
