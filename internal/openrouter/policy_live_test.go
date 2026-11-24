package openrouter

import (
	"context"
	"os"
	"testing"

	"antispambee/internal/detection"
	"antispambee/internal/moderation"
)

// Opt-in probe: reports the model's actual decisions without Telegram actions.
// It uses the supplied OpenRouter key and incurs API usage only when enabled.
func TestLiveJevCompactPolicy(t *testing.T) {
	if os.Getenv("ANTISPAMBEE_JEV_LIVE_TEST") != "1" {
		t.Skip("set ANTISPAMBEE_JEV_LIVE_TEST=1 to evaluate real Jev answers")
	}
	client, err := NewClient(ClientConfig{APIKey: os.Getenv("OPENROUTER_API_KEY"), BaseURL: os.Getenv("OPENROUTER_BASE_URL"), Model: os.Getenv("OPENROUTER_MODEL")})
	if err != nil {
		t.Fatal(err)
	}
	matched, falsePositives, failures := 0, 0, 0
	for _, tc := range []struct {
		id, text string
		ad       bool
	}{
		{"54127", "Сделаю: сайт, приложения, тг бота Все в лс", true},
		{"54124", "Ищу траффера пишите в лс", true},
		{"54109", "Дам ворк 500-800$ в день, закладки кидать не надо", true},
		{"54060", "Скупаю акки плеерка с отзывами писать в лс", true},
		{"54040", "Дам ворк 500-800$, не закладки и тд", true},
		{"54008", "Купите у меня гпт плюс", true},
		{"53967", "Возьму МТС Айди 14$ любое гео @seller", true},
		{"53915", "6$ гк мтс физ срочно хаб авто бью сам", true},
		{"53825", "Куплю акк плеерка минимум 100 отзывов писать в лс", true},
		{"ham_greeting", "Привет всем", false},
		{"ham_question", "Где купить GPT Plus?", false},
		{"ham_discussion", "GPT Plus стоит 20$ в месяц", false},
		{"ham_warning", "Осторожно мошенники! Дам ворк 500-800$ в день", false},
	} {
		signal := client.AnalyzeAdvertising(context.Background(), detection.SemanticAdContent{Message: detection.MessageContent{Text: tc.text}})
		if signal.Status != detection.StatusAvailable || signal.Score == nil || signal.Confidence == nil {
			failures++
			t.Logf("JEV_CASE id=%s status=%s reasons=%v", tc.id, signal.Status, signal.ReasonCodes)
			continue
		}
		decision := moderation.NewDecisionEngine().Decide(moderation.DecisionInput{
			Target:            moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
			HasMessageContent: true, Signals: []detection.Signal{signal},
		})
		deleted := decision.AuthorizedAction == moderation.ActionDeleteMessage
		if tc.ad && deleted {
			matched++
		}
		if !tc.ad && deleted {
			falsePositives++
		}
		t.Logf("JEV_CASE id=%s expected_ad=%t score=%.3f confidence=%.3f coverage=%.2f action=%s model=%s", tc.id, tc.ad, *signal.Score, *signal.Confidence, signal.EvidenceCoverage, decision.AuthorizedAction, signal.ResolvedModel)
	}
	// Deliberately report misses instead of weakening production thresholds.
	t.Logf("JEV_SUMMARY ads_authorized=%d/9 ham_deleted=%d/4 api_failures=%d", matched, falsePositives, failures)
	if failures > 0 || falsePositives > 0 {
		t.Errorf("live evaluation needs attention: API failures=%d false positives=%d", failures, falsePositives)
	}
}
