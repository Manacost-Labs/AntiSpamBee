package detection

import (
	"regexp"
	"strings"
)

var compactOfferPricePattern = regexp.MustCompile(`(?i)(?:^|[^\pL\pN])(?:[$€₽]\s*[1-9][0-9]*(?:[.,][0-9]{1,2})?|[1-9][0-9]*(?:[.,][0-9]{1,2})?\s*(?:[$€₽]|usd\b|eur\b|руб(?:лей|ля|ль)?\.?))`)
var compactOfferContactPattern = regexp.MustCompile(`@[a-zA-Z][a-zA-Z0-9_]{3,31}\b`)

const (
	ReasonServiceOffer     = "SERVICE_OFFER"
	ReasonAccountTrade     = "ACCOUNT_TRADE"
	ReasonSubscriptionSale = "SUBSCRIPTION_SALE"
	ReasonInformalJobOffer = "INFORMAL_JOB_OFFER"
	ReasonOpaqueTradeOffer = "OPAQUE_TRADE_OFFER"
)

// detectCompactOffers recognizes complete short solicitations without requiring
// a website. Price alone, topic mentions, and requests for advice are insufficient.
func detectCompactOffers(value string, hasLink bool, rulePrefix string) (float64, []string, []string) {
	text := normalize(value)
	if compactOfferDiscussion(text) {
		return 0, nil, nil
	}
	contact := hasLink || compactOfferContactPattern.MatchString(value) || containsAny(text,
		"в лс", "в личку", "в личные", "пишите", "писать", "пиши", "обращайтесь", "заказывайте")
	price := compactOfferPricePattern.MatchString(value)
	serviceVerb := containsOfferToken(text, "сделаю", "разработаю", "создам", "настрою", "напишу", "сверстаю")
	service := containsAny(text, "приложени", "логотип", "дизайн", "верстк") ||
		containsOfferToken(text, "сайт", "сайты", "сайтов", "бот", "бота", "ботов", "боты")
	serviceOffer := serviceVerb && service && contact
	trafficRecruitment := containsAny(text, "ищу траффера", "ищем траффера", "нужен траффер",
		"нужны трафферы", "ищу трафферов", "ищем трафферов") && contact
	workOffer := containsAny(text, "дам ворк", "даем ворк", "даю ворк", "предлагаю ворк") && (price || contact)
	trade := containsOfferToken(text, "куплю", "скупаю", "покупаю", "продам", "продаю", "продажа", "купите")
	account := containsAny(text, "аккаунт") || containsOfferToken(text, "акк", "акки", "акков", "акка", "учетки", "учетку")
	accountTrade := trade && account && (contact || price || containsAny(text, "отзыв", "плеерк", "плеерок", "playerok"))
	subscription := containsAny(text, "гпт плюс", "gpt plus", "chatgpt plus", "чатгпт плюс")
	subscriptionSale := trade && subscription
	identity := containsAny(text, "мтс айди", "мтс id", "mts id")
	identityTrade := identity && containsOfferToken(text, "возьму", "куплю", "скупаю", "покупаю", "продам", "продаю") && (price || contact)
	// The abbreviations are opaque. Match the observed trading cluster, not
	// all mentions of MTS, physical SIMs, currency amounts, or individual words.
	opaqueTrade := price && containsToken(text, "гк") && containsToken(text, "мтс") &&
		containsToken(text, "физ") && containsToken(text, "срочно") &&
		(containsOfferToken(text, "хаб", "авто") || containsAny(text, "бью сам"))
	reasons, rules := []string{}, []string{}
	for _, match := range []struct {
		matched bool
		reason  string
		rule    string
	}{
		{serviceOffer, ReasonServiceOffer, "SERVICE_OFFER"},
		{trafficRecruitment || workOffer, ReasonInformalJobOffer, "INFORMAL_JOB_OFFER"},
		{accountTrade || identityTrade, ReasonAccountTrade, "ACCOUNT_TRADE"},
		{subscriptionSale, ReasonSubscriptionSale, "SUBSCRIPTION_SALE"},
		{opaqueTrade, ReasonOpaqueTradeOffer, "OPAQUE_TRADE_OFFER"},
	} {
		if match.matched {
			reasons = appendUnique(reasons, ReasonCommercialPromotion, match.reason)
			rules = append(rules, rulePrefix+match.rule)
		}
	}
	if len(rules) == 0 {
		return 0, reasons, rules
	}
	return .95, reasons, rules
}

func containsOfferToken(text string, tokens ...string) bool {
	for _, token := range tokens {
		if containsToken(text, token) {
			return true
		}
	}
	return false
}

func compactOfferDiscussion(text string) bool {
	if containsAny(text, "не куплю", "не скупаю", "не покупаю", "не продаю", "не продам",
		"мне написали", "мне прислали", "разбор рекламы", "цитирую", "цитата", "пример рекламы") {
		return true
	}
	for _, prefix := range []string{"кто пишет ", "что значит ", "где купить ", "как купить ", "кто продает "} {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}
