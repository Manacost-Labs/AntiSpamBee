package detection

import (
	"slices"
	"testing"
	"time"
)

func TestMessageAdDetectorFlagsScreenshotVPNPromotion(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	detector := newMessageAdDetector(func() time.Time { return now })

	signal := detector.Analyze(MessageContent{
		Text: `📢 NordVPN — Бесплатный ВПН
⚡ Зачем платить 500 ₽ за тормозящий VPN, если есть этот?
Хватит сливать деньги на подписку, которые отваливаются через неделю…
VPN с которым летает Telegram, TikTok, YouTube — БЕСПЛАТНО`,
		HasLink: true,
	})

	if signal.Status != StatusAvailable {
		t.Fatalf("status = %q, want AVAILABLE", signal.Status)
	}
	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
	if signal.Severity != SeverityHigh {
		t.Errorf("severity = %q, want HIGH", signal.Severity)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonCommercialPromotion) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonCommercialPromotion)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonVPNPromotion) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonVPNPromotion)
	}
	if signal.CreatedAt != now {
		t.Errorf("created at = %s, want %s", signal.CreatedAt, now)
	}
}

func TestMessageAdDetectorFlagsVPNOfferBehindTextLink(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	signal := detector.Analyze(MessageContent{
		Text:    "Бесплатный VPN — установи и забудь про блокировки",
		HasLink: true,
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
}

func TestMessageAdDetectorFlagsGenericCommercialOffer(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	signal := detector.Analyze(MessageContent{
		Text:    "Скидка 50% по промокоду BEE. Заказывай сейчас по ссылке",
		HasLink: true,
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonCommercialPromotion) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonCommercialPromotion)
	}
	if slices.Contains(signal.ReasonCodes, ReasonVPNPromotion) {
		t.Errorf("reason codes = %v, do not want %q", signal.ReasonCodes, ReasonVPNPromotion)
	}
}

func TestMessageAdDetectorFlagsProhibitedAdTypes(t *testing.T) {
	detector := newMessageAdDetector(time.Now)
	tests := []struct {
		name   string
		text   string
		reason string
	}{
		{
			name:   "gambling",
			text:   "Казино: бонус 500% за первый депозит. Забрать по ссылке",
			reason: ReasonGamblingPromotion,
		},
		{
			name:   "crypto scam",
			text:   "Гарантированная прибыль 20% в неделю на крипте без риска. Вступай сейчас",
			reason: ReasonCryptoPromotion,
		},
		{
			name:   "payday loan",
			text:   "Займ без отказа за 5 минут. Оформить сейчас",
			reason: ReasonLoanPromotion,
		},
		{
			name:   "mass job offer",
			text:   "Нужны сотрудники на удаленную работу. Высокий доход, пишите в личку",
			reason: ReasonMassJobOffer,
		},
		{
			name:   "adult channel",
			text:   "Порно канал 18+. Подписывайся и смотри видео по ссылке",
			reason: ReasonAdultContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signal := detector.Analyze(MessageContent{Text: tt.text, HasLink: true})
			if signal.Score == nil || *signal.Score < 0.9 {
				t.Fatalf("score = %v, want at least 0.9", signal.Score)
			}
			if !slices.Contains(signal.ReasonCodes, tt.reason) {
				t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, tt.reason)
			}
		})
	}
}

func TestMessageAdDetectorDoesNotFlagNeutralSensitiveTopics(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	for _, text := range []string{
		"Обсуждаем регулирование казино и ставок",
		"Изучаю блокчейн, криптовалюты и инвестиции",
		"Сегодня полностью закрыл кредит",
		"Исследование зависимости от порно и её влияния на отношения",
		"Обсуждаем состояние рынка труда и удаленную работу",
	} {
		signal := detector.Analyze(MessageContent{Text: text, HasLink: true})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("text %q: score = %v, want 0", text, signal.Score)
		}
	}
}

func TestMessageAdDetectorDoesNotFlagNeutralVPNDiscussion(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	for _, text := range []string{
		"Какой бесплатный VPN сейчас работает?",
		"NordVPN перестал подключаться после обновления",
		"Обсуждаем влияние блокировок VPN на пользователей",
	} {
		signal := detector.Analyze(MessageContent{Text: text})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("text %q: score = %v, want 0", text, signal.Score)
		}
	}
}

func TestMessageAdDetectorDoesNotFlagOrdinaryLinkedMessage(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	for _, text := range []string{
		"Вот ссылка на документацию проекта",
		"Сегодня обсуждаем скидки в разных магазинах",
	} {
		signal := detector.Analyze(MessageContent{Text: text, HasLink: true})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("text %q: score = %v, want 0", text, signal.Score)
		}
	}
}

func TestMessageAdDetectorReturnsMissingWithoutMessageText(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	signal := detector.Analyze(MessageContent{})

	if signal.Status != StatusMissing {
		t.Fatalf("status = %q, want MISSING", signal.Status)
	}
	if signal.Score != nil || signal.Confidence != nil {
		t.Fatalf("score = %v, confidence = %v; want nil", signal.Score, signal.Confidence)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonNoMessageText) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonNoMessageText)
	}
}
