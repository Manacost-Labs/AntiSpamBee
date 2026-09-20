package openrouter

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"antispambee/internal/detection"
	"antispambee/internal/moderation"
)

func TestModelDeletionRequiresStrongConsistentEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, category, evidence string
		wantDelete               bool
	}{
		{"missing", "commercial", "", false},
		{"ambiguous", "commercial", `,"evidence_strength":{"type":"score","score":1,"confidence":0.99}`, false},
		{"uncertain", "commercial", `,"evidence_strength":{"type":"score","score":2,"confidence":0.5}`, false},
		{"invalid", "commercial", `,"evidence_strength":{"type":"score","score":3,"confidence":0.99}`, false},
		{"wrong_type", "commercial", `,"evidence_strength":{"type":"noul","score":2,"confidence":0.99}`, false},
		{"contradictory", "none", `,"evidence_strength":{"type":"score","score":2,"confidence":0.99}`, false},
		{"strong", "commercial", `,"evidence_strength":{"type":"score","score":1.95,"confidence":0.99}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"answers":{"evidence_passage":{"type":"choice","choice":"p0","confidence":0.99},"is_prohibited_ad":{"type":"noul","noul":0.99},"ad_category":{"type":"choice","choice":%q,"confidence":0.99}%s}}`, tc.category, tc.evidence)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{APIKey: "test", BaseURL: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{Message: detection.MessageContent{Text: "Купить подписку, пиши в лс"}})
			decision := moderation.NewDecisionEngine().Decide(moderation.DecisionInput{Target: moderation.ActionTarget{Kind: moderation.TargetMessage}, HasMessageContent: true, Signals: []detection.Signal{signal}})
			if got := decision.AuthorizedAction == moderation.ActionDeleteMessage; got != tc.wantDelete {
				t.Fatalf("delete=%v want=%v: %+v", got, tc.wantDelete, signal)
			}
		})
	}
}

func TestEvidencePassageMustBeAnActualMessageExcerpt(t *testing.T) {
	for _, choice := range []string{"none", "invented", "p32", ""} {
		t.Run(choice, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				fmt.Fprintf(w, `{"answers":{"evidence_passage":{"type":"choice","choice":%q,"confidence":0.99},"is_prohibited_ad":{"type":"noul","noul":0.99},"ad_category":{"type":"choice","choice":"commercial","confidence":0.99},"evidence_strength":{"type":"score","score":2,"confidence":0.99}}}`, choice)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{APIKey: "test", BaseURL: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			s := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{Message: detection.MessageContent{Text: "Купить подписку"}})
			if s.EvidenceCoverage != 0 || s.EvidenceExcerpt != "" {
				t.Fatal("invented passage accepted")
			}
		})
	}
	m := detection.MessageContent{Text: strings.Repeat("я", 14000), Caption: "caption", OCRText: "OCR"}
	passages := messagePassages(m)
	if len(passages) != 32 {
		t.Fatalf("unbounded passages: %d", len(passages))
	}
	for _, p := range passages {
		if len([]rune(p)) > 400 || !strings.Contains(m.Text, p) {
			t.Fatal("not a bounded literal excerpt")
		}
	}
}
