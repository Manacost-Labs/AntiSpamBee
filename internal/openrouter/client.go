package openrouter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"antispambee/internal/detection"
)

const (
	defaultBaseURL = "https://openrouter.ai"
	defaultModel   = "~typesafe/jev-latest"
)

// ClientConfig configures OpenRouter Decisions API access.
type ClientConfig struct {
	APIKey     string
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

// Client evaluates text-only Telegram context with TypeSafe Jev.
type Client struct {
	apiKey     string
	baseURL    string
	model      string
	httpClient *http.Client
	now        func() time.Time
}

// NewClient creates an OpenRouter Decisions API client.
func NewClient(config ClientConfig) (*Client, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("OpenRouter API key is required")
	}
	baseURL := config.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	parsedURL, err := url.Parse(baseURL)
	if err != nil || !safeAPIBaseURL(parsedURL) {
		return nil, fmt.Errorf("OpenRouter base URL is invalid")
	}
	model := config.Model
	if model == "" {
		model = defaultModel
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		apiKey:     config.APIKey,
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      model,
		httpClient: httpClient,
		now:        time.Now,
	}, nil
}

func safeAPIBaseURL(value *url.URL) bool {
	if value == nil || value.Host == "" {
		return false
	}
	if value.Scheme == "https" {
		return true
	}
	if value.Scheme != "http" {
		return false
	}
	host := value.Hostname()
	return host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
}

// AnalyzeAdvertising returns a shadow detector signal and never performs an
// automatic moderation action.
func (c *Client) AnalyzeAdvertising(ctx context.Context, content detection.SemanticAdContent) detection.Signal {
	signal := detection.Signal{
		SchemaVersion:   "1",
		Detector:        "model.jev_advertising",
		DetectorVersion: "jev-openrouter-v1",
		Category:        "spam.advertising",
		ReasonCodes:     []string{},
		MatchedRules:    []string{},
		CreatedAt:       c.now().UTC(),
	}
	state, coverage := semanticState(content)
	if coverage == 0 {
		signal.Status = detection.StatusMissing
		signal.Severity = detection.SeverityInfo
		signal.ReasonCodes = []string{detection.ReasonNoSemanticContent}
		return signal
	}

	response, err := c.decide(ctx, state)
	if err != nil {
		signal.Status = detection.StatusError
		signal.Severity = detection.SeverityInfo
		signal.ReasonCodes = []string{detection.ReasonOpenRouterFailed}
		return signal
	}
	prohibited, ok := response.Answers["is_prohibited_ad"]
	if !ok || prohibited.Type != "noul" || prohibited.Noul == nil || *prohibited.Noul < 0 || *prohibited.Noul > 1 {
		signal.Status = detection.StatusError
		signal.Severity = detection.SeverityInfo
		signal.ReasonCodes = []string{detection.ReasonOpenRouterFailed}
		return signal
	}
	category, ok := response.Answers["ad_category"]
	if !ok || category.Type != "choice" || !knownCategory(category.Choice) || category.Confidence == nil ||
		*category.Confidence < 0 || *category.Confidence > 1 {
		signal.Status = detection.StatusError
		signal.Severity = detection.SeverityInfo
		signal.ReasonCodes = []string{detection.ReasonOpenRouterFailed}
		return signal
	}

	score := *prohibited.Noul
	confidence := *category.Confidence
	signal.Status = detection.StatusAvailable
	signal.Score = &score
	signal.Confidence = &confidence
	signal.EvidenceCoverage = coverage
	signal.Severity = semanticSeverity(score)
	if score >= 0.5 {
		signal.ReasonCodes = append(signal.ReasonCodes, detection.ReasonCommercialPromotion)
	}
	if category.Choice != "none" {
		if reason := categoryReason(category.Choice); reason != "" {
			signal.ReasonCodes = append(signal.ReasonCodes, reason)
		}
		signal.MatchedRules = append(signal.MatchedRules, "JEV_CATEGORY_"+strings.ToUpper(category.Choice))
	}
	if score >= 0.9 {
		signal.MatchedRules = append(signal.MatchedRules, "JEV_PROHIBITED_AD_01")
	}
	return signal
}

type decisionsResponse struct {
	Answers map[string]decisionAnswer `json:"answers"`
}

type decisionAnswer struct {
	Type       string   `json:"type"`
	Noul       *float64 `json:"noul"`
	Choice     string   `json:"choice"`
	Confidence *float64 `json:"confidence"`
}

func (c *Client) decide(ctx context.Context, state map[string]any) (decisionsResponse, error) {
	payload := map[string]any{
		"model": c.model,
		"state": state,
		"questions": map[string]any{
			"is_prohibited_ad": map[string]any{
				"type":         "noul",
				"instructions": "Does the Telegram content actively promote, solicit, or advertise a prohibited commercial offer rather than discuss the topic neutrally?",
				"criteria": map[string]string{
					"true":  "An active promotion, solicitation, recruitment pitch, or call to obtain a prohibited product or service.",
					"false": "Neutral discussion, criticism, news, support request, personal conversation, or insufficient evidence of promotion.",
				},
			},
			"ad_category": map[string]any{
				"type":         "choice",
				"instructions": "Classify the primary advertising category. Choose none when this is not an active promotion.",
				"criteria": map[string]string{
					"none":       "Not advertising or evidence is insufficient.",
					"job_scam":   "Mass recruitment, easy remote work, or unrealistic income solicitation.",
					"adult":      "Pornography, sexual services, or paid adult content promotion.",
					"vpn":        "VPN service promotion or subscription offer.",
					"gambling":   "Casino, betting, slots, bookmaker, bonus, or deposit promotion.",
					"crypto":     "Crypto or investment offer promising returns, signals, or low-risk profit.",
					"loan":       "Loan or credit promotion, especially easy or guaranteed approval.",
					"commercial": "Another explicit product, service, discount, referral, or promotional offer.",
				},
			},
			"evidence_strength": map[string]any{
				"type":         "score",
				"instructions": "Rate how directly the supplied content demonstrates active advertising.",
				"criteria": []string{
					"Insufficient: neutral topic mention or no promotion.",
					"Ambiguous: some promotional cues but plausible benign interpretation.",
					"Strong: explicit offer plus benefit, price, link, contact, or call to action.",
				},
			},
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return decisionsResponse{}, fmt.Errorf("encode OpenRouter decision request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/api/alpha/decisions",
		bytes.NewReader(body),
	)
	if err != nil {
		return decisionsResponse{}, fmt.Errorf("create OpenRouter decision request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+c.apiKey)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return decisionsResponse{}, fmt.Errorf("send OpenRouter decision request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return decisionsResponse{}, fmt.Errorf("OpenRouter Decisions API returned HTTP %d", response.StatusCode)
	}
	var result decisionsResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&result); err != nil {
		return decisionsResponse{}, fmt.Errorf("decode OpenRouter decision response: %w", err)
	}
	return result, nil
}

func semanticState(content detection.SemanticAdContent) (map[string]any, float64) {
	state := map[string]any{}
	messageText := strings.TrimSpace(strings.Join([]string{content.Message.Text, content.Message.Caption}, " "))
	if messageText != "" {
		state["message_text"] = messageText
		state["message_has_link"] = content.Message.HasLink
		if len(content.Message.URLs) > 0 {
			state["message_urls"] = content.Message.URLs
		}
	}
	if content.Profile.Username != "" {
		state["profile_username"] = content.Profile.Username
	}
	if content.Profile.Bio != "" {
		state["profile_bio"] = content.Profile.Bio
	}
	if channel := content.Profile.PersonalChannel; channel != nil {
		state["personal_channel"] = map[string]any{
			"title":        channel.Title,
			"username":     channel.Username,
			"description":  channel.Description,
			"recent_posts": channel.RecentPosts,
		}
	}
	if len(state) == 0 {
		return state, 0
	}
	coverage := 0.5
	if messageText != "" && (content.Profile.Bio != "" || content.Profile.PersonalChannel != nil) {
		coverage = 1
	}
	return state, coverage
}

func categoryReason(category string) string {
	switch category {
	case "job_scam":
		return detection.ReasonMassJobOffer
	case "adult":
		return detection.ReasonAdultContent
	case "vpn":
		return detection.ReasonVPNPromotion
	case "gambling":
		return detection.ReasonGamblingPromotion
	case "crypto":
		return detection.ReasonCryptoPromotion
	case "loan":
		return detection.ReasonLoanPromotion
	default:
		return ""
	}
}

func knownCategory(category string) bool {
	switch category {
	case "none", "job_scam", "adult", "vpn", "gambling", "crypto", "loan", "commercial":
		return true
	default:
		return false
	}
}

func semanticSeverity(score float64) detection.Severity {
	if score >= 0.9 {
		return detection.SeverityHigh
	}
	if score >= 0.7 {
		return detection.SeverityMedium
	}
	return detection.SeverityInfo
}
