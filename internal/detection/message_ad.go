package detection

import (
	"regexp"
	"strings"
	"time"
)

var jobMoneyAmountPattern = regexp.MustCompile(`(?i)(?:[1-9][0-9]{2,6}|[1-9][0-9]{0,2}[ .][0-9]{3})\s*(?:₽|руб(?:лей|ля|ль)?\.?)`)
var percentageReturnPattern = regexp.MustCompile(`(?i)\b\d{1,3}\s*%\s*(?:в|за)\s*(?:день|недел|месяц)`)
var likelyLinkPattern = regexp.MustCompile(`(?i)(?:https?://|(?:t|telegram)\.me/|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:ru|com|net|org|io|me|ai|app|site|online|xyz|рф)(?:/|\b))`)
var obfuscatedLinkPattern = regexp.MustCompile(`(?i)(?:(?:t|telegram)\s*(?:\[\s*\.\s*\]|\(\s*\.\s*\)|\s+(?:dot|точка)\s+)\s*me(?:/|\b)|\b[a-z0-9][a-z0-9-]*\s*\[\s*\.\s*\]\s*(?:ru|com|net|org|io|me|ai|app|site|online|xyz)(?:/|\b))`)

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
	OCRText string
	HasLink bool
	URLs    []string
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
		DetectorVersion: "message-ad-v3",
		Category:        "spam.advertising",
		ReasonCodes:     []string{},
		MatchedRules:    []string{},
		CreatedAt:       d.now().UTC(),
	}

	combined := strings.TrimSpace(strings.Join([]string{content.Text, content.Caption, content.OCRText}, " "))
	if combined == "" {
		base.Status = StatusMissing
		base.Severity = SeverityInfo
		base.ReasonCodes = []string{ReasonNoMessageText}
		return base
	}

	hasLink := content.HasLink || containsLikelyLink(combined)
	score, reasons, rules := detectCommercialPromotion(combined, hasLink, "MESSAGE_AD_")
	restrictedScore, restrictedReasons, restrictedRules := detectRestrictedPromotion(combined, hasLink, "MESSAGE_AD_")
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
	if score >= .9 && containsAny(normalize(combined),
		"осторожно мошенники", "это мошенники", "это мошенничество", "это спам",
		"не переходите по ссылке", "не переходи по ссылке", "мне прислали", "пример спама",
		"beware of scammers", "this is a scam", "do not click", "spam example") {
		// Context is ambiguous, not proven benign: retain the risk for review.
		// A separate semantic detector may still find active promotion.
		base.EvidenceCoverage = 0
		base.ReasonCodes = appendUnique(base.ReasonCodes, "POSSIBLE_QUOTATION_OR_WARNING")
	}
	return base
}

func detectRestrictedPromotion(combined string, hasLink bool, rulePrefix string) (float64, []string, []string) {
	text := normalize(combined)
	massRecruitment := containsAny(text,
		"нужны сотрудники", "требуются сотрудники", "ищу сотрудников", "ищем сотрудников",
		"набор сотрудников", "набираем команду", "ищу людей", "ищем людей",
	)
	employmentHook := containsAny(text,
		"частичная занятость", "частичную занятость", "удаленная работа", "удаленную работу", "работа из дома",
		"свободный график", "подработка",
	) || containsSegmentedJobKeyword(text)
	moneyHook := containsAny(text,
		"высокий доход", "стабильный доход", "заработок", "без вложений", "в день",
	)
	jobCTA := containsAny(text,
		"пиши в личку", "пишите в личку", "пиши в лс", "пишите в лс", "подробности в лич",
	)
	jobPromotion := massRecruitment && employmentHook && (moneyHook || jobCTA || hasLink)
	directJobPitch := massRecruitment || containsAny(text,
		"ищем подработку", "предлагаем подработку", "есть подработка", "подработка для",
		"подработка от", "требуется на подработку", "требуются на подработку", "набор на подработку",
	) || containsSegmentedJobKeyword(text)
	directMessageCTA := jobCTA || containsAny(text,
		"в лс", "в личку", "в личные сообщения", "в директ", "в личные", "писать", "связь через",
	)
	compactJobPromotion := directJobPitch && jobMoneyAmountPattern.MatchString(combined) && directMessageCTA
	jobContext := employmentHook || containsAny(text,
		"требуется менеджер", "требуются менеджеры", "работа 2 часа", "работа на дому", "вакансия",
	)
	jobPayment := jobMoneyAmountPattern.MatchString(combined) || containsAny(text,
		"выплата", "оплата", "доход", "зарплата", "10к", "20к", "30к",
	)
	compactJobPromotion = compactJobPromotion || (jobContext && jobPayment && directMessageCTA)

	adultMention := containsAny(text,
		"onlyfans", "онлифанс", "нюдсы", "интимные фото", "интимные видео", "секс чат",
		"вебкам", "webcam", "порно канал", "porn channel",
	) || containsToken(text, "xxx")
	adultCTA := containsAny(text,
		"подписывайся", "подпишись", "subscribe", "доступ в канал", "смотри видео",
		"смотреть видео", "приватный контент", "private content",
	)
	adultPromotion := adultMention && (adultCTA || hasLink)
	ageMarker := strings.Contains(strings.ToLower(combined), "18+") || strings.Contains(combined, "🔞")
	adultEuphemism := ageMarker && containsAny(text,
		"девочки", "девушки", "приват", "private", "контент для взрослых",
	) && (hasLink || containsAny(text, "канал", "группа", "подпис"))

	score := 0.0
	reasons := []string{}
	rules := []string{}
	if jobPromotion {
		score = 0.93
		reasons = appendUnique(reasons, ReasonCommercialPromotion, ReasonMassJobOffer)
		rules = append(rules, rulePrefix+"JOB_01")
	}
	if compactJobPromotion {
		if score < 0.97 {
			score = 0.97
		}
		reasons = appendUnique(reasons, ReasonCommercialPromotion, ReasonMassJobOffer)
		rules = append(rules, rulePrefix+"JOB_COMPACT_01")
	}
	if adultPromotion || adultEuphemism {
		if score < 0.95 {
			score = 0.95
		}
		reasons = appendUnique(reasons, ReasonCommercialPromotion, ReasonAdultContent)
		rules = append(rules, rulePrefix+"ADULT_01")
	}
	return score, reasons, rules
}

func containsLikelyLink(value string) bool {
	return likelyLinkPattern.MatchString(value) || obfuscatedLinkPattern.MatchString(value)
}

func containsSegmentedKeyword(value, keyword string) bool {
	fields := strings.Fields(value)
	wanted := foldConfusables(strings.ReplaceAll(normalize(keyword), " ", ""))
	wantedLength := len([]rune(wanted))
	for start := range fields {
		joined := ""
		for end := start; end < len(fields); end++ {
			joined += fields[end]
			length := len([]rune(joined))
			if length > wantedLength {
				break
			}
			if end > start && foldConfusables(joined) == wanted {
				return true
			}
		}
	}
	return false
}

func containsSegmentedJobKeyword(value string) bool {
	for _, keyword := range []string{"подработка", "подработку", "подработки", "подработке", "подработкой"} {
		if containsSegmentedKeyword(value, keyword) {
			return true
		}
	}
	return false
}

func detectCommercialPromotion(combined string, hasLink bool, rulePrefix string) (float64, []string, []string) {
	text := normalize(combined)
	vpnFolded := strings.NewReplacer("р", "p", "ν", "v").Replace(text)
	vpnMention := containsToken(text, "vpn") || strings.Contains(vpnFolded, "vpn") ||
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
		"без блокировок",
		"без ограничений",
		"подключайся",
	)
	promotionClaim := containsAny(text,
		"летают все соц сети",
		"летают все соцсети",
		"работают все соц сети",
		"работают все соцсети",
		"быстрый vpn",
		"быстрый впн",
		"только у нас",
		"наш vpn",
		"наш впн",
	)

	vpnPromotion := vpnMention && ((freeHook && (priceHook || activationHook || hasLink)) ||
		(priceHook && (activationHook || hasLink)) ||
		(activationHook && hasLink) ||
		(promotionClaim && hasLink))
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
	channelPromotion := hasLink && containsAny(text, "канал", "группа", "сообщество") && containsAny(text,
		"подпишись", "подписывайся", "подписаться", "наш канал", "в нашем канале",
	)
	shopPromotion := hasLink && containsAny(text, "лучшие цены", "низкие цены", "каталог", "в наличии") && containsAny(text,
		"цены", "каталог", "заказ", "доставка", "магазин",
	)
	giveawayPromotion := hasLink && containsAny(text, "розыгрыш", "разыгрываем", "выиграй") && containsAny(text,
		"приз", "подарок", "iphone", "айфон", "забери", "получи",
	)
	genericPromotion = genericPromotion || channelPromotion || shopPromotion || giveawayPromotion

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
	gamblingPromotion = gamblingPromotion || (gamblingMention && hasLink && containsAny(text,
		"прогноз", "заходят", "коэффициент", "экспресс", "в нашем канале",
	))

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
	cryptoPromotion = cryptoPromotion || (cryptoMention && (percentageReturnPattern.MatchString(combined) || containsAny(text, "сигналы в лс", "сигналы в лич")) && hasLink)

	loanMention := containsAny(text,
		"займ", "микрозайм", "кредит", "деньги до зарплаты", "деньги срочно",
	)
	loanHook := containsAny(text,
		"без отказа", "без отказов", "без проверки", "без справок", "за 5 минут", "за пять минут", "одобрение всем",
	)
	loanCTA := containsAny(text,
		"оформить", "получить деньги", "подать заявку", "оставить заявку", "заявка на сайте", "бери сейчас",
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
