package detection

import (
	"strings"
	"time"
)

const (
	ReasonCommercialPromotion = "COMMERCIAL_PROMOTION"
	ReasonVPNPromotion        = "VPN_PROMOTION"
	ReasonGamblingPromotion   = "GAMBLING_PROMOTION"
	ReasonCryptoPromotion     = "CRYPTO_INVESTMENT_PROMOTION"
	ReasonLoanPromotion       = "LOAN_PROMOTION"
	ReasonNoMessageText       = "NO_MESSAGE_TEXT"
)

// MessageContent is the Telegram message content available to text detectors.
type MessageContent struct {
	Text    string
	Caption string
	HasLink bool
}

// MessageAdDetector detects prohibited commercial promotion in messages.
type MessageAdDetector struct {
	now func() time.Time
}

// NewMessageAdDetector creates the current deterministic message-ad rules.
func NewMessageAdDetector() *MessageAdDetector {
	return newMessageAdDetector(time.Now)
}

func newMessageAdDetector(now func() time.Time) *MessageAdDetector {
	return &MessageAdDetector{now: now}
}

// Analyze evaluates message text without performing a moderation action.
func (d *MessageAdDetector) Analyze(content MessageContent) Signal {
	base := Signal{
		SchemaVersion:   "1",
		Detector:        "message.commercial_promotion",
		DetectorVersion: "message-ad-v2",
		Category:        "spam.advertising",
		ReasonCodes:     []string{},
		MatchedRules:    []string{},
		CreatedAt:       d.now().UTC(),
	}

	combined := strings.TrimSpace(strings.Join([]string{content.Text, content.Caption}, " "))
	if combined == "" {
		base.Status = StatusMissing
		base.Severity = SeverityInfo
		base.ReasonCodes = []string{ReasonNoMessageText}
		return base
	}

	score, reasons, rules := detectCommercialPromotion(combined, content.HasLink, "MESSAGE_AD_")
	restrictedScore, restrictedReasons, restrictedRules := detectRestrictedMessagePromotion(combined, content.HasLink)
	if restrictedScore > score {
		score = restrictedScore
	}
	reasons = appendUnique(reasons, restrictedReasons...)
	rules = append(rules, restrictedRules...)
	confidence := 0.92
	base.Status = StatusAvailable
	base.EvidenceCoverage = 1
	base.Score = &score
	base.Confidence = &confidence
	base.Severity = severityFor(score)
	base.ReasonCodes = reasons
	base.MatchedRules = rules
	return base
}

func detectRestrictedMessagePromotion(combined string, hasLink bool) (float64, []string, []string) {
	text := normalize(combined)
	massRecruitment := containsAny(text,
		"нужны сотрудники", "требуются сотрудники", "ищу сотрудников", "ищем сотрудников",
		"набор сотрудников", "набираем команду", "ищу людей", "ищем людей",
	)
	employmentHook := containsAny(text,
		"частичная занятость", "частичную занятость", "удаленная работа", "удаленную работу", "работа из дома",
		"свободный график", "подработка",
	)
	moneyHook := containsAny(text,
		"высокий доход", "стабильный доход", "заработок", "без вложений", "в день",
	)
	jobCTA := containsAny(text,
		"пиши в личку", "пишите в личку", "пиши в лс", "пишите в лс", "подробности в лич",
	)
	jobPromotion := massRecruitment && employmentHook && (moneyHook || jobCTA || hasLink)

	adultMention := containsAny(text,
		"onlyfans", "онлифанс", "нюдсы", "интимные фото", "интимные видео", "секс чат",
		"вебкам", "webcam", "порно канал", "porn channel",
	) || containsToken(text, "xxx")
	adultCTA := containsAny(text,
		"подписывайся", "подпишись", "subscribe", "доступ в канал", "смотри видео",
		"смотреть видео", "приватный контент", "private content",
	)
	adultPromotion := adultMention && (adultCTA || hasLink)

	score := 0.0
	reasons := []string{}
	rules := []string{}
	if jobPromotion {
		score = 0.93
		reasons = appendUnique(reasons, ReasonCommercialPromotion, ReasonMassJobOffer)
		rules = append(rules, "MESSAGE_AD_JOB_01")
	}
	if adultPromotion {
		if score < 0.95 {
			score = 0.95
		}
		reasons = appendUnique(reasons, ReasonCommercialPromotion, ReasonAdultContent)
		rules = append(rules, "MESSAGE_AD_ADULT_01")
	}
	return score, reasons, rules
}

func detectCommercialPromotion(combined string, hasLink bool, rulePrefix string) (float64, []string, []string) {
	text := normalize(combined)
	vpnMention := containsToken(text, "vpn") ||
		containsToken(text, "впн") ||
		containsAny(text, "nordvpn", "expressvpn", "protonvpn", "surfshark")
	freeHook := containsAny(text, "бесплатн", "free vpn", "free access")
	priceHook := containsAny(text,
		"зачем платить",
		"хватит платить",
		"сливать деньги",
		"деньги на подписку",
		"экономия",
		"дешевле",
	) || strings.Contains(combined, "₽")
	activationHook := containsAny(text,
		"установи",
		"установить",
		"скачай",
		"скачать",
		"подключи",
		"подключить",
		"получи доступ",
		"переходи",
		"летает telegram",
		"обход блокировок",
		"забудь про блокировки",
	)

	vpnPromotion := vpnMention && ((freeHook && (priceHook || activationHook || hasLink)) ||
		(priceHook && (activationHook || hasLink)) ||
		(activationHook && hasLink))
	offerHook := containsAny(text,
		"скидка",
		"промокод",
		"распродажа",
		"специальное предложение",
		"бонус при покупке",
		"акция только",
	)
	commercialCallToAction := containsAny(text,
		"заказывай",
		"заказать сейчас",
		"купи сейчас",
		"купить сейчас",
		"оформляй",
		"переходи по ссылке",
		"забрать по ссылке",
		"регистрируйся",
	)
	genericPromotion := hasLink && offerHook && commercialCallToAction

	gamblingMention := containsAny(text,
		"казино", "casino", "ставки", "ставок", "букмекер", "беттинг", "слоты",
	)
	gamblingHook := containsAny(text,
		"бонус", "фрибет", "промокод", "за депозит", "первый депозит", "выигрыш",
	)
	gamblingCTA := containsAny(text,
		"забрать", "получить бонус", "играй", "начни играть", "делай ставку", "регистрируйся",
	)
	gamblingPromotion := gamblingMention && gamblingHook && (gamblingCTA || hasLink)

	cryptoMention := containsAny(text,
		"крипт", "crypto", "bitcoin", "биткоин", "инвестиц", "трейдинг", "trading",
	)
	cryptoPromise := containsAny(text,
		"гарантированная прибыль", "гарантированный доход", "без риска", "доход в неделю",
		"прибыль в неделю", "удвоить депозит", "торговые сигналы", "пассивный доход",
	)
	cryptoCTA := containsAny(text,
		"вступай", "присоединяйся", "инвестируй", "начни зарабатывать", "пиши в личку", "пиши в лс",
	)
	cryptoPromotion := cryptoMention && cryptoPromise && (cryptoCTA || hasLink)

	loanMention := containsAny(text,
		"займ", "микрозайм", "кредит", "деньги до зарплаты",
	)
	loanHook := containsAny(text,
		"без отказа", "без проверки", "без справок", "за 5 минут", "за пять минут", "одобрение всем",
	)
	loanCTA := containsAny(text,
		"оформить", "получить деньги", "подать заявку", "оставить заявку", "бери сейчас",
	)
	loanPromotion := loanMention && loanHook && (loanCTA || hasLink)

	score := 0.0
	reasons := []string{}
	rules := []string{}
	if genericPromotion {
		score = 0.93
		reasons = appendUnique(reasons, ReasonCommercialPromotion)
		rules = append(rules, rulePrefix+"GENERIC_01")
	}
	if vpnPromotion {
		score = 0.95
		reasons = appendUnique(
			reasons,
			ReasonCommercialPromotion,
			ReasonVPNPromotion,
		)
		rules = append(rules, rulePrefix+"VPN_01")
	}
	for _, match := range []struct {
		matched bool
		reason  string
		rule    string
	}{
		{gamblingPromotion, ReasonGamblingPromotion, "GAMBLING_01"},
		{cryptoPromotion, ReasonCryptoPromotion, "CRYPTO_01"},
		{loanPromotion, ReasonLoanPromotion, "LOAN_01"},
	} {
		if !match.matched {
			continue
		}
		if score < 0.95 {
			score = 0.95
		}
		reasons = appendUnique(reasons, ReasonCommercialPromotion, match.reason)
		rules = append(rules, rulePrefix+match.rule)
	}
	return score, reasons, rules
}
