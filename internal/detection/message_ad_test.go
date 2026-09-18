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

func TestMessageAdDetectorNormalizesObfuscatedJobSpam(t *testing.T) {
	detector := NewMessageAdDetector()
	signal := detector.Analyze(MessageContent{
		Text:    "Нужны сотрудники, уд@ленная работа, высокий з@р@б0ток. Пишите в личку",
		HasLink: true,
	})
	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
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

func TestMessageAdDetectorFlagsExclusiveVPNPerformanceClaim(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	signal := detector.Analyze(MessageContent{
		Text:    "VPN с которым летают все соц сети только у нас vpn.ru",
		HasLink: true,
	})

	if signal.Score == nil || *signal.Score < 0.9 || *signal.Score >= 1 {
		t.Fatalf("score = %v, want delete-only risk in [0.9, 1)", signal.Score)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonVPNPromotion) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonVPNPromotion)
	}
	if !slices.Contains(signal.MatchedRules, "MESSAGE_AD_VPN_01") {
		t.Errorf("matched rules = %v, want MESSAGE_AD_VPN_01", signal.MatchedRules)
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

func TestMessageAdDetectorFlagsCompactJobPromotionWithAmountAndDirectMessageCTA(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	for _, text := range []string{
		"ИЩЕМ ПОДРАБОТКУ 5000 РУБЛЕЙ В ЛС",
		"Есть подработка — 5 000 руб. Пиши в личку",
		"Требуются на подработку. Оплата 7500₽, подробности в директ",
		"Подработка для всех от 3000 рублей, в личные сообщения",
	} {
		signal := detector.Analyze(MessageContent{Text: text})

		if signal.Score == nil || *signal.Score < 0.9 || *signal.Score >= 1 {
			t.Fatalf("text %q: score = %v, want delete-only risk in [0.9, 1)", text, signal.Score)
		}
		if !slices.Contains(signal.ReasonCodes, ReasonCommercialPromotion) {
			t.Errorf("text %q: reason codes = %v, want %q", text, signal.ReasonCodes, ReasonCommercialPromotion)
		}
		if !slices.Contains(signal.ReasonCodes, ReasonMassJobOffer) {
			t.Errorf("text %q: reason codes = %v, want %q", text, signal.ReasonCodes, ReasonMassJobOffer)
		}
		if !slices.Contains(signal.MatchedRules, "MESSAGE_AD_JOB_COMPACT_01") {
			t.Errorf("text %q: matched rules = %v, want MESSAGE_AD_JOB_COMPACT_01", text, signal.MatchedRules)
		}
	}
}

func TestMessageAdDetectorDoesNotFlagIncompleteCompactJobPromotion(t *testing.T) {
	detector := newMessageAdDetector(time.Now)

	for _, text := range []string{
		"Ищу подработку, готов обсудить условия",
		"На прошлой подработке получил 5000 рублей",
		"Ищем подработку для школьного проекта с бюджетом 5000 рублей",
		"Ищем подработку, пишите в ЛС",
	} {
		signal := detector.Analyze(MessageContent{Text: text})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("text %q: score = %v, want 0", text, signal.Score)
		}
	}
}

func TestMessageAdDetectorGoldenSpamVariants(t *testing.T) {
	detector := newMessageAdDetector(time.Now)
	cases := []MessageContent{
		{Text: "Работа 2 часа в день, выплата 10к, писать @manager"},
		{Text: "Требуется менеджер, доход 5000 в день, пиши в ЛС"},
		{Text: "Подпишись на наш канал t.me/best_channel", HasLink: true},
		{Text: "Лучшие цены на кроссовки, каталог shop.ru", HasLink: true},
		{Text: "Разыгрываем iPhone, забери приз по ссылке", HasLink: true},
		{Text: "VРN без блокировок, подключайся vpn.ru", HasLink: true},
		{Text: "Ставки заходят каждый день, прогнозы в нашем канале", HasLink: true},
		{Text: "Крипта даёт 20% в месяц, сигналы в ЛС", HasLink: true},
		{Text: "Деньги срочно без отказов, заявка на сайте", HasLink: true},
		{Text: "18+ девочки, приват в нашем канале", HasLink: true},
	}
	for _, content := range cases {
		signal := detector.Analyze(content)
		if signal.Score == nil || *signal.Score < 0.9 {
			t.Errorf("text %q: score = %v, want at least 0.9", content.Text, signal.Score)
		}
	}
}

func TestMessageAdDetectorGoldenHamVariants(t *testing.T) {
	detector := newMessageAdDetector(time.Now)
	for _, text := range []string{
		"Ищу работу менеджером, ожидаю зарплату 5000 рублей",
		"Обсуждаем ставки Центрального банка",
		"Сегодня полностью закрыл кредит без просрочек",
		"Приватный репозиторий проекта находится на GitHub",
		"Розыгрыш мяча привёл к победному голу",
	} {
		signal := detector.Analyze(MessageContent{Text: text})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("text %q: score = %v, want 0", text, signal.Score)
		}
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
