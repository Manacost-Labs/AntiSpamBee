package detection

import (
	"slices"
	"strings"
	"time"
)

const (
	ProhibitedChannelDetectorName = "profile.prohibited_channel"
	ReasonConfirmedAdultChannel   = "CONFIRMED_ADULT_CHANNEL"
	ReasonConfirmedFraudChannel   = "CONFIRMED_FRAUD_CHANNEL"
)

// AnalyzeProhibited examines channel identity and individual complete posts.
// Unlike advertising-only classification, unrelated or captionless posts do
// not negate positive evidence. Profile bio cannot supply channel evidence.
func (d *AdvertisingChannelDetector) AnalyzeProhibited(profile Profile) Signal {
	signal := Signal{
		SchemaVersion: "1", Detector: ProhibitedChannelDetectorName,
		DetectorVersion: "prohibited-channel-v2", Category: "spam.profile",
		Status: StatusMissing, Severity: SeverityInfo,
		ReasonCodes: []string{ReasonNoPersonalChannel}, MatchedRules: []string{},
		CreatedAt: time.Now().UTC(),
	}
	channel := profile.PersonalChannel
	if channel == nil {
		return signal
	}
	score, confidence := 0.0, .99
	signal.Status, signal.Score, signal.Confidence = StatusAvailable, &score, &confidence
	signal.ReasonCodes = []string{ReasonUnconfirmedChannelContent}
	metadata := strings.TrimSpace(channel.Title + " " + channel.Description)
	if channelContentDiscussion(metadata) {
		return signal
	}
	// Title and description describe the channel itself; a bare age marker,
	// username, or platform name does not establish prohibited content.
	texts := append([]string{metadata}, channel.RecentPosts...)
	for i, text := range texts {
		if strings.TrimSpace(text) == "" || channelContentDiscussion(text) {
			continue
		}
		privateAdult := i > 0 && privateAdultChannelFunnel(text, channel)
		adult := explicitAdultChannelContent(text) || privateAdult
		if i > 0 {
			post := d.analyzeChannelPost(text, channel)
			adult = adult || (confirmedChannelOffer(text, post) && slices.Contains(post.ReasonCodes, ReasonAdultContent))
		}
		fraud := fraudulentChannelOffer(text)
		if !adult && !fraud {
			continue
		}
		score = 1
		signal.Severity, signal.EvidenceCoverage = SeverityHigh, 1
		if signal.EvidenceExcerpt == "" {
			signal.EvidenceExcerpt = strings.TrimSpace(text)
			if privateAdult {
				signal.EvidenceExcerpt = metadata + "\n" + signal.EvidenceExcerpt
			}
			signal.ReasonCodes = []string{}
		}
		if adult {
			signal.ReasonCodes = appendUnique(signal.ReasonCodes, ReasonConfirmedAdultChannel, ReasonAdultContent)
			rule := "CHANNEL_EXPLICIT_ADULT_CONTENT"
			if privateAdult {
				rule = "CHANNEL_ADULT_PRIVATE_FUNNEL"
			}
			signal.MatchedRules = appendUnique(signal.MatchedRules, rule)
		}
		if fraud {
			signal.ReasonCodes = appendUnique(signal.ReasonCodes, ReasonConfirmedFraudChannel)
			signal.MatchedRules = appendUnique(signal.MatchedRules, "CHANNEL_FRAUDULENT_OFFER")
		}
	}
	return signal
}

// Require a private Telegram invite and corroborating adult content in the
// same post. Neither an intimate channel name nor an uncensored slogan alone
// establishes a private adult funnel.
func privateAdultChannelFunnel(post string, channel *PersonalChannel) bool {
	invite := containsAny(strings.ToLower(post), "t.me/+", "t.me/joinchat/")
	if !invite {
		return false
	}
	identity := channel.Title + " " + channel.Description
	name := normalize(identity)
	text := normalize(post)
	// Some channels omit age markers and emoji, advertising striptease through
	// a private MILF identity and a sexual headline instead.
	private := containsToken(name, "приват") || containsToken(name, "private")
	milf := containsToken(name, "милфы") || containsToken(name, "милфа") ||
		containsToken(name, "milf") || containsToken(name, "milfs")
	striptease := containsAny(text, "разделась на камеру", "раздевается на камеру")
	if private && milf && striptease {
		return true
	}
	intimate := containsAny(name, "мой секрет", "мои секреты",
		"личный архив", "секретный архив", "приват", "закрытая коллекция") &&
		containsAny(identity, "😘", "💋", "🔞", "🍑")
	uncensored := containsAny(text, "без цензуры", "без ограничений", "uncensored")
	access := containsAny(text, "заявка открывает доступ", "доступ по заявке",
		"вход по заявке", "request access")
	return intimate && uncensored && access
}

func channelContentDiscussion(value string) bool {
	return possibleChannelPromotionWarning(value) || containsAny(normalize(value),
		"не отправляйте деньги", "не переводите деньги", "защита от мошен",
		"борьба с мошен", "разоблачение", "сексуальное образование", "половое воспитание",
		"сексуальное здоровье", "психология", "зависимость", "вред порно", "против порно",
		"без порно", "без эротики", "не публикуем порно", "no porn",
		"sex education", "sexual health", "porn addiction", "scam warning")
}

func explicitAdultChannelContent(value string) bool {
	text := normalize(value)
	return containsAny(text,
		"порно", "эротика", "эротическ", "интимные фото", "интимные видео",
		"интимный контент", "интим контент", "голые девушки", "обнаженные девушки",
		"сливы девушек", "сливы онлифанс", "сливы onlyfans",
		"porn", "nudes", "sex videos", "adult videos", "nsfw") ||
		hasAgeMarker(value) && containsAny(text, "горячие ролики", "горячие видео",
			"горячие девочки", "горячие девушки", "интим", "секс знакомства", "сливы")
}

// Ordinary jobs, investment discussion, and a cryptocurrency label are not
// fraud evidence. Each candidate must contain the scheme and its solicitation.
func fraudulentChannelOffer(value string) bool {
	text := normalize(value)
	contact := containsLikelyLink(value) || containsAny(text,
		"пиши", "пишите", "в личку", "в лс", "переведи", "переведите",
		"отправь", "отправьте", "внеси", "внесите", "оплати", "оплатите",
		"send", "deposit", "contact", "dm me")
	if !contact {
		return false
	}
	financial := containsAny(text, "прибыль", "доход", "инвест", "вложен", "деньги",
		"депозит", "крипт", "profit", "return", "invest", "money")
	guaranteed := containsAny(text, "гарантирован", "гарантирую", "гарантируем", "guaranteed")
	riskFree := containsAny(text, "без риска", "без рисков", "никаких рисков", "risk free", "risk-free")
	doubling := containsAny(text, "удвою", "удвоим", "удвоение", "умножу", "умножим",
		"раскрутка депозита", "раскрутка твоего депозита", "раскрутка счета", "double your money")
	job := containsAny(text, "работ", "ваканси", "подработ", "job")
	upfront := containsAny(text, "взнос для начала работы", "оплата для начала работы",
		"оплатите доступ к работе", "оплати доступ к работе", "оплатить доступ к работе",
		"страховой взнос", "активация рабочего кабинета", "активацию рабочего кабинета",
		"pay to start", "pay for job access")
	prize := containsAny(text, "выигрыш", "выиграли", "приз", "победитель")
	prizeFee := containsAny(text, "оплатите комиссию", "оплати комиссию", "оплатить комиссию",
		"оплатите налог", "оплати налог", "переведите комиссию")
	return financial && (guaranteed && riskFree || doubling) || job && upfront || prize && prizeFee
}
