package openrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"antispambee/internal/detection"
)

func TestClientAnalyzeAdvertisingUsesDecisionsAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/alpha/decisions" {
			t.Fatalf("path = %q, want /api/alpha/decisions", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Fatalf("Authorization = %q", got)
		}
		var request struct {
			Model     string                     `json:"model"`
			State     map[string]any             `json:"state"`
			Questions map[string]json.RawMessage `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if request.Model != "~typesafe/jev-latest" {
			t.Errorf("model = %q", request.Model)
		}
		if request.State["message_text"] != "Казино: бонус за депозит" {
			t.Errorf("state = %#v", request.State)
		}
		for _, question := range []string{"is_prohibited_ad", "ad_category", "evidence_strength"} {
			if _, ok := request.Questions[question]; !ok {
				t.Errorf("question %q missing", question)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"dec-1",
			"model":"typesafe/jev-1.13",
			"provider":"TypeSafe",
			"answers":{
				"is_prohibited_ad":{"type":"noul","noul":0.97},
				"ad_category":{"type":"choice","choice":"gambling","probabilities":{"gambling":0.94,"none":0.06},"confidence":0.91},
				"evidence_strength":{"type":"score","score":1.9,"confidence":0.88,"probabilities":{"0":0.01,"1":0.08,"2":0.91},"legend":{"0":"insufficient","1":"ambiguous","2":"strong"}}
			},
			"usage":{"input_tokens":120,"output_tokens":20,"cost":0.000005}
		}`))
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{
		APIKey:     "test-secret",
		BaseURL:    server.URL,
		Model:      "~typesafe/jev-latest",
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{
		Message: detection.MessageContent{Text: "Казино: бонус за депозит", HasLink: true},
		Profile: detection.Profile{Bio: "Забрать бонус: t.me/win"},
	})

	if signal.Status != detection.StatusAvailable {
		t.Fatalf("status = %q, want AVAILABLE", signal.Status)
	}
	if signal.Score == nil || *signal.Score != 0.97 {
		t.Fatalf("score = %v, want 0.97", signal.Score)
	}
	if signal.Confidence == nil || *signal.Confidence != 0.91 {
		t.Fatalf("confidence = %v, want 0.91", signal.Confidence)
	}
	if !slices.Contains(signal.ReasonCodes, detection.ReasonGamblingPromotion) {
		t.Errorf("reason codes = %v", signal.ReasonCodes)
	}
	if !slices.Contains(signal.MatchedRules, "JEV_PROHIBITED_AD_01") {
		t.Errorf("matched rules = %v", signal.MatchedRules)
	}
}

func TestClientAnalyzeAdvertisingReturnsErrorSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"code":529,"message":"overloaded"}}`, http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client, err := NewClient(ClientConfig{APIKey: "test-secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{
		Message: detection.MessageContent{Text: "реклама"},
	})

	if signal.Status != detection.StatusError {
		t.Fatalf("status = %q, want ERROR", signal.Status)
	}
	if signal.Score != nil || signal.Confidence != nil {
		t.Fatalf("score = %v, confidence = %v; want nil", signal.Score, signal.Confidence)
	}
	if !slices.Contains(signal.ReasonCodes, detection.ReasonOpenRouterFailed) {
		t.Errorf("reason codes = %v", signal.ReasonCodes)
	}
}

func TestClientAnalyzeAdvertisingSkipsEmptyContent(t *testing.T) {
	client, err := NewClient(ClientConfig{APIKey: "test-secret"})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{})

	if signal.Status != detection.StatusMissing {
		t.Fatalf("status = %q, want MISSING", signal.Status)
	}
}

func TestClientAnalyzeAdvertisingRejectsInvalidConfidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"model":"typesafe/jev-1.13",
			"answers":{
				"is_prohibited_ad":{"type":"noul","noul":0.95},
				"ad_category":{"type":"choice","choice":"commercial","confidence":1.2}
			},
			"usage":{"input_tokens":10,"output_tokens":2}
		}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{APIKey: "test-secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{
		Message: detection.MessageContent{Text: "Скидка, купить сейчас"},
	})

	if signal.Status != detection.StatusError {
		t.Fatalf("status = %q, want ERROR", signal.Status)
	}
}

func TestClientAnalyzeAdvertisingRecordsGenericCategory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"model":"typesafe/jev-1.13",
			"answers":{
				"is_prohibited_ad":{"type":"noul","noul":0.95},
				"ad_category":{"type":"choice","choice":"commercial","confidence":0.9}
			},
			"usage":{"input_tokens":10,"output_tokens":2}
		}`))
	}))
	defer server.Close()
	client, err := NewClient(ClientConfig{APIKey: "test-secret", BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{
		Message: detection.MessageContent{Text: "Скидка, купить сейчас"},
	})

	if !slices.Contains(signal.MatchedRules, "JEV_CATEGORY_COMMERCIAL") {
		t.Fatalf("matched rules = %v", signal.MatchedRules)
	}
}
