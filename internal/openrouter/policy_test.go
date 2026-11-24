package openrouter

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"antispambee/internal/detection"
)

func TestPolicyExamplesAreReferenceOnly(t *testing.T) {
	for _, choice := range []string{"p0", "example_01", "example_09", "moderation_policy"} {
		t.Run(choice, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request struct {
					State     map[string]json.RawMessage `json:"state"`
					Questions map[string]struct {
						Instructions string          `json:"instructions"`
						Criteria     json.RawMessage `json:"criteria"`
					} `json:"questions"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Fatal(err)
				}
				var policy string
				if err := json.Unmarshal(request.State["moderation_policy"], &policy); err != nil {
					t.Fatal(err)
				}
				for i := 1; i <= 9; i++ {
					if !strings.Contains(policy, fmt.Sprintf("example_%02d", i)) {
						t.Errorf("reference example %d missing", i)
					}
				}
				var passages map[string]string
				if err := json.Unmarshal(request.State["message_passages"], &passages); err != nil {
					t.Fatal(err)
				}
				if len(passages) != 1 || passages["p0"] != "Привет всем" {
					t.Fatalf("reference examples leaked into source passages: %v", passages)
				}
				for id, question := range request.Questions {
					if !strings.Contains(question.Instructions, "moderation_policy") || !strings.Contains(question.Instructions, "current message") && !strings.Contains(question.Instructions, "current-message") {
						t.Errorf("question %s does not scope its evidence to the message", id)
					}
				}
				var criteria map[string]string
				if err := json.Unmarshal(request.Questions["evidence_passage"].Criteria, &criteria); err != nil {
					t.Fatal(err)
				}
				if len(criteria) != 2 || criteria["p0"] == "" || criteria["none"] == "" {
					t.Fatalf("reference examples became selectable evidence: %v", criteria)
				}
				fmt.Fprintf(w, `{"answers":{"evidence_passage":{"type":"choice","choice":%q,"confidence":0.99},"is_prohibited_ad":{"type":"noul","noul":0.99},"ad_category":{"type":"choice","choice":"commercial","confidence":0.99},"evidence_strength":{"type":"score","score":2,"confidence":0.99}}}`, choice)
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{APIKey: "test", BaseURL: server.URL, HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{Message: detection.MessageContent{Text: "Привет всем"}})
			if choice != "p0" && (signal.EvidenceExcerpt != "" || signal.EvidenceCoverage != 0) {
				t.Fatalf("reference example authorized message enforcement: %+v", signal)
			}
		})
	}
}
