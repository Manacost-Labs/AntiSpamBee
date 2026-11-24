package openrouter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"antispambee/internal/detection"
)

func TestAnalyzeContentValidatesEvidenceOrigin(t *testing.T) {
	const offer = "Подписка на сервис. Месяц за 700 ₽, пишите в ЛС."
	for _, test := range []struct {
		name, source, evidence, prefix string
		image                          bool
		want                           bool
	}{
		{name: "message text", source: "message", evidence: offer, want: true},
		{name: "quote punctuation normalized", source: "message", evidence: "Подписка на сервис — месяц за 700 ₽; пишите в ЛС", want: true},
		{name: "profile quote used as message", source: "bio", evidence: "Ремонт часов, записывайтесь в ЛС"},
		{name: "invented quote", source: "message", evidence: "Купите экспертный курс прямо сейчас"},
		{name: "warning with verbatim offer", source: "message", prefix: "Осторожно, это спам. Мне прислали:\n", evidence: offer},
		{name: "image supplied", source: "image", evidence: "На баннере видна цена подписки и призыв купить", image: true, want: true},
		{name: "image absent", source: "image", evidence: "На баннере видна цена подписки и призыв купить"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path != "/api/v1/chat/completions" {
					t.Errorf("path = %q", req.URL.Path)
				}
				var input map[string]any
				if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
					t.Error(err)
				}
				encoded, _ := json.Marshal(input)
				if strings.Contains(string(encoded), "private_username") || strings.Contains(string(encoded), "data:image/png;base64,") != test.image {
					t.Error("unexpected username or image payload")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"model": "test-vision", "choices": []any{map[string]any{
					"finish_reason": "stop", "message": map[string]string{"content": jsonString(map[string]any{
						"message": map[string]string{"verdict": "advertising", "source": test.source, "evidence": test.evidence},
						"profile": map[string]string{"verdict": "advertising", "source": "bio", "evidence": "Ремонт часов, записывайтесь в ЛС"},
					})},
				}}})
			}))
			defer server.Close()
			client, err := NewClient(ClientConfig{APIKey: "mock", BaseURL: server.URL, Model: "test-vision"})
			if err != nil {
				t.Fatal(err)
			}
			input := detection.SemanticAdContent{
				Message: detection.MessageContent{Text: test.prefix + "Подписка на сервис.\nМесяц за 700 ₽, пишите в ЛС."},
				Profile: detection.Profile{Username: "private_username", Bio: "Ремонт часов, записывайтесь в ЛС"},
			}
			if test.image {
				input.Image = []byte("\x89PNG\r\n\x1a\nmock")
			}
			signals := client.AnalyzeContent(context.Background(), input)
			if len(signals) != 2 || signals[0].EvidenceCoverage == 1 != test.want || signals[1].EvidenceCoverage != 1 {
				t.Fatalf("signals = %+v", signals)
			}
		})
	}
}

func jsonString(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestProfileImageRequiresPublicChannelAndMatchingSource(t *testing.T) {
	channel := &detection.PersonalChannel{Username: "public_channel", RecentPosts: []string{"", "Подпись"}}
	input := detection.SemanticAdContent{
		Profile:       detection.Profile{PersonalChannel: channel},
		ProfileImages: []detection.ProfileImage{{PostNumber: 2, Data: []byte("\x89PNG\r\n\x1a\nmock")}},
	}
	verdict := contentVerdict{Verdict: "advertising", Source: "channel_image_2", Evidence: "Объявление с ценой и контактом для записи"}
	images := contentImages(input)
	if !validContentEvidence(detection.SemanticProfileDetector, verdict, nil, images) {
		t.Fatal("did not recognize the image from the correct public channel post")
	}
	if validContentEvidence(detection.SemanticMessageDetector, verdict, nil, images) {
		t.Fatal("a profile image cannot prove advertising in the current message")
	}
	channel.Username = ""
	if images := contentImages(input); len(images) != 0 {
		t.Fatal("an image from a non-public profile channel was included")
	}
}

func TestContentDistinguishesTransientOutages(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { w.WriteHeader(status) }))
			defer server.Close()
			client, err := NewClient(ClientConfig{APIKey: "mock", BaseURL: server.URL, Model: "test-vision"})
			if err != nil {
				t.Fatal(err)
			}
			signals := client.AnalyzeContent(context.Background(), detection.SemanticAdContent{Message: detection.MessageContent{Text: "Привет"}})
			if len(signals) != 1 || signals[0].Status != detection.StatusError {
				t.Fatalf("expected unavailable backend signal, got %+v", signals)
			}
			if temporary := slices.Contains(signals[0].ReasonCodes, detection.ReasonOpenRouterTemporarilyUnavailable); temporary != (status != http.StatusUnauthorized) {
				t.Fatalf("unexpected transient status for %d: %t", status, temporary)
			}
		})
	}
}

func TestAnalyzeContentLive(t *testing.T) {
	model := os.Getenv("ANTISPAMBEE_CONTENT_LIVE_MODEL")
	if model == "" {
		t.Skip("set ANTISPAMBEE_CONTENT_LIVE_MODEL to exercise the OpenRouter API")
	}
	client, err := NewClient(ClientConfig{APIKey: os.Getenv("OPENROUTER_API_KEY"), BaseURL: os.Getenv("OPENROUTER_BASE_URL"), Model: model})
	if err != nil {
		t.Fatal(err)
	}
	imagePath := os.Getenv("ANTISPAMBEE_CONTENT_LIVE_IMAGE")
	if imagePath == "" {
		t.Fatal("a synthetic advertisement image is required")
	}
	image, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, text   string
		profile      detection.Profile
		image        []byte
		profileImage []byte
		want         [2]bool
	}{
		{name: "apartment payout", text: "Приветствую, нужно будет помочь забрать вещи со съемной квартиры, каждому получится 6000", want: [2]bool{true, false}},
		{name: "unseen service", text: "Сведу ваш подкаст и уберу шум. 12 евро за выпуск, заказывайте в личке.", want: [2]bool{true, false}},
		{name: "profile channel", text: "Наконец собрал колоду", profile: detection.Profile{PersonalChannel: &detection.PersonalChannel{
			Title: "Высшее и среднее образование 1-2 месяца", RecentPosts: []string{"Помогаем получить официально высшее и среднее образование всего за 1–3 месяца! Подписывайся: https://example.com"},
		}}, want: [2]bool{false, true}},
		{name: "advertising channel with neutral title", text: "Удобно, что всё в одном месте", profile: detection.Profile{PersonalChannel: &detection.PersonalChannel{
			Title: "Stay Weird", RecentPosts: []string{
				"Зарабатывай 25к–170к в месяц без вложений. Обучение и приватные схемы бесплатно, обращайся в нашу команду.",
				"Нужны сотрудники на частичную занятость. Оплата 8 000 рублей за 4–6 часов работы. Чтобы откликнуться, напишите в личку.",
			},
		}}, want: [2]bool{false, true}},
		{name: "profile professional", text: "Какая колода лучше?", profile: detection.Profile{Bio: "Звукорежиссёр и музыкант, люблю подкасты"}},
		{name: "scam warning", text: "Осторожно, это спам! Мне прислали: Сведу ваш подкаст за 12 евро, заказывайте в личке."},
		{name: "card pack discussion", text: "Такой бред, что дают карты из события, если ты просто купил пак. Так они ещё и срезают этот срок до одной недели"},
		{name: "short reply", text: "Не будет"},
		{name: "frustration", text: "Ну пиздец"},
		{name: "moderator count", text: "только 1 мод? обычно же по 2"},
		{name: "image only", image: image, want: [2]bool{true, false}},
		{name: "profile image only", text: "Люблю играть на магах", profileImage: image,
			profile: detection.Profile{PersonalChannel: &detection.PersonalChannel{
				Username: "public_school", Title: "Запись на уроки гитары", RecentPosts: []string{""},
			}}, want: [2]bool{false, true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := detection.SemanticAdContent{
				Message: detection.MessageContent{Text: test.text}, Profile: test.profile, Image: test.image,
			}
			if len(test.profileImage) > 0 {
				input.ProfileImages = []detection.ProfileImage{{PostNumber: 1, Data: test.profileImage}}
			}
			signals := client.AnalyzeContent(context.Background(), input)
			if len(signals) != 2 {
				t.Fatalf("did not get both verdicts: %+v", signals)
			}
			for index, signal := range signals {
				if signal.Status != detection.StatusAvailable || (signal.EvidenceCoverage == 1) != test.want[index] {
					t.Errorf("detector %s, got coverage %.1f and reasons %v, expected enforced=%t", signal.Detector, signal.EvidenceCoverage, signal.ReasonCodes, test.want[index])
				}
			}
		})
	}
}
