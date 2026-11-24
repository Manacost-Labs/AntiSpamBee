package detection

import (
	"slices"
	"strings"
	"time"
)

const (
	AdvertisingChannelDetectorName         = "profile.advertising_channel"
	ReasonConfirmedAdvertisingChannel      = "CONFIRMED_ADVERTISING_CHANNEL"
	ReasonConfirmedAdultAdvertisingChannel = "CONFIRMED_ADULT_ADVERTISING_CHANNEL"
	ReasonUnconfirmedChannelContent        = "UNCONFIRMED_CHANNEL_CONTENT"
)

// AdvertisingChannelDetector confirms a channel dedicated to advertising.
// Every sampled post must contain a complete promotional offer. Metadata and
// fragments from different posts cannot supply missing evidence.
type AdvertisingChannelDetector struct {
	messages *MessageAdDetector
}

func NewAdvertisingChannelDetector() *AdvertisingChannelDetector {
	return &AdvertisingChannelDetector{messages: NewMessageAdDetector()}
}

func (d *AdvertisingChannelDetector) Analyze(profile Profile) Signal {
	signal := Signal{
		SchemaVersion:   "1",
		Detector:        AdvertisingChannelDetectorName,
		DetectorVersion: "advertising-channel-v4",
		Category:        "spam.advertising",
		Status:          StatusMissing,
		Severity:        SeverityInfo,
		ReasonCodes:     []string{ReasonNoPersonalChannel},
		MatchedRules:    []string{},
		CreatedAt:       time.Now().UTC(),
	}
	channel := profile.PersonalChannel
	if channel == nil {
		return signal
	}
	score, confidence := 0.0, 0.95
	signal.Status = StatusAvailable
	signal.Score, signal.Confidence = &score, &confidence
	signal.ReasonCodes = []string{ReasonUnconfirmedChannelContent}
	if len(channel.RecentPosts) == 0 {
		return signal
	}
	if possibleChannelPromotionWarning(channel.Title + " " + channel.Description) {
		return signal
	}

	reasons := []string{ReasonConfirmedAdvertisingChannel}
	rules := []string{"CHANNEL_ALL_SAMPLED_POSTS_PROMOTIONAL"}
	allAdult := true
	for _, post := range channel.RecentPosts {
		postSignal := d.analyzeChannelPost(post, channel)
		if !confirmedChannelOffer(post, postSignal) {
			return signal
		}
		allAdult = allAdult && slices.Contains(postSignal.ReasonCodes, ReasonAdultContent)
		reasons = appendUnique(reasons, postSignal.ReasonCodes...)
		rules = append(rules, postSignal.MatchedRules...)
	}
	// A personal description contradicts an advertising-only sample. A plain
	// adult description can corroborate posts that all actively advertise access.
	if description := strings.TrimSpace(channel.Description); description != "" &&
		!confirmedChannelOffer(description, d.analyzeChannelPost(description, channel)) &&
		!(allAdult && hasAdultChannelContext(description)) {
		return signal
	}
	score = 0.95
	if allAdult {
		score, confidence = 1, .99
		reasons = appendUnique(reasons, ReasonConfirmedAdultAdvertisingChannel)
		rules = append(rules, "CHANNEL_ALL_SAMPLED_POSTS_ADULT_PROMOTION")
	}
	signal.Severity = SeverityHigh
	signal.EvidenceCoverage = 1
	signal.EvidenceExcerpt = channel.RecentPosts[0]
	signal.ReasonCodes = reasons
	signal.MatchedRules = rules
	return signal
}

func (d *AdvertisingChannelDetector) analyzeChannelPost(post string, channel *PersonalChannel) Signal {
	signal := d.messages.Analyze(MessageContent{Text: post})
	if possibleChannelPromotionWarning(post) {
		signal.EvidenceCoverage = 0
		return signal
	}
	// The 18+ label often lives in the channel title, while its post uses
	// euphemisms. Require adult context, sexual media, a CTA and a link together.
	text := normalize(post)
	adultContext := hasAdultChannelContext(post + " " + channel.Title + " " + channel.Description)
	sexualMedia := containsAny(text, "горячие ролики", "горячие видео", "горячие видосы",
		"интимные ролики", "интимные видео", "приватные видео", "видео для взрослых")
	accessCTA := containsAny(text, "доступ по заявке", "по заявке в канал", "доступ в канал",
		"подписывайся", "подпишись", "вступай", "переходи", "смотри видео", "смотреть видео")
	if adultContext && sexualMedia && accessCTA && containsLikelyLink(post) {
		score, confidence := .95, .95
		signal.Status = StatusAvailable
		signal.Score, signal.Confidence = &score, &confidence
		signal.Severity = SeverityHigh
		signal.EvidenceCoverage = 1
		signal.ReasonCodes = appendUnique(signal.ReasonCodes, ReasonCommercialPromotion, ReasonAdultContent)
		signal.MatchedRules = append(signal.MatchedRules, "CHANNEL_ADULT_CONTEXT_AND_ACCESS_OFFER")
	}
	return signal
}

func hasAdultChannelContext(value string) bool {
	return hasAgeMarker(value) ||
		containsAny(normalize(value), "порно", "onlyfans", "онлифанс", "интим",
			"контент для взрослых", "видео для взрослых")
}

func possibleChannelPromotionWarning(value string) bool {
	return IsPromotionWarning(value) || containsAny(normalize(value),
		"разбор рекламы", "разбор мошен", "предупреждение", "цитирую", "цитата",
		"пример рекламы", "не вступайте", "не подписывайтесь")
}

func confirmedChannelOffer(post string, signal Signal) bool {
	if signal.Status != StatusAvailable || signal.Score == nil || *signal.Score < .9 ||
		signal.EvidenceCoverage < .5 {
		return false
	}
	if slices.Contains(signal.ReasonCodes, ReasonMassJobOffer) {
		text := normalize(post)
		// Require an actual payment offer and contact instruction, not just a
		// channel name, an employment topic, or a truncated recruitment headline.
		return jobMoneyAmountPattern.MatchString(post) && containsAny(text,
			"без вложений", "частичную занятость", "частичная занятость",
			"подработка", "удаленная работа", "работа из дома", "час",
		) && (containsLikelyLink(post) || containsAny(text,
			"пишите", "пиши", "писать", "свяжитесь", "обращайтесь", "подробности в лич",
		))
	}
	for _, reason := range []string{ReasonAdultContent, ReasonVPNPromotion,
		ReasonGamblingPromotion, ReasonCryptoPromotion, ReasonLoanPromotion, ReasonEducationDocumentOffer} {
		if slices.Contains(signal.ReasonCodes, reason) {
			return true
		}
	}
	// Ordinary music releases, personal links, and generic self-promotion do not
	// establish that an account is using its channel to advertise prohibited offers.
	return false
}
