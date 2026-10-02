package detection

import (
	"slices"
	"strings"
	"time"
)

const (
	AdvertisingChannelDetectorName    = "profile.advertising_channel"
	ReasonConfirmedAdvertisingChannel = "CONFIRMED_ADVERTISING_CHANNEL"
	ReasonUnconfirmedChannelContent   = "UNCONFIRMED_CHANNEL_CONTENT"
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
		DetectorVersion: "advertising-channel-v1",
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

	reasons := []string{ReasonConfirmedAdvertisingChannel}
	rules := []string{"CHANNEL_ALL_SAMPLED_POSTS_PROMOTIONAL"}
	for _, post := range channel.RecentPosts {
		postSignal := d.messages.Analyze(MessageContent{Text: post})
		if !confirmedChannelOffer(post, postSignal) {
			return signal
		}
		reasons = appendUnique(reasons, postSignal.ReasonCodes...)
		rules = append(rules, postSignal.MatchedRules...)
	}
	// A personal channel description contradicts an advertising-only sample.
	// Unclear descriptions remain for review rather than being combined with posts.
	if description := strings.TrimSpace(channel.Description); description != "" &&
		!confirmedChannelOffer(description, d.messages.Analyze(MessageContent{Text: description})) {
		return signal
	}
	score = 0.95
	signal.Severity = SeverityHigh
	signal.EvidenceCoverage = 1
	signal.EvidenceExcerpt = channel.RecentPosts[0]
	signal.ReasonCodes = reasons
	signal.MatchedRules = rules
	return signal
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
		ReasonGamblingPromotion, ReasonCryptoPromotion, ReasonLoanPromotion} {
		if slices.Contains(signal.ReasonCodes, reason) {
			return true
		}
	}
	// Ordinary music releases, personal links, and generic self-promotion do not
	// establish that an account is using its channel to advertise prohibited offers.
	return false
}
