package detection

import (
	"strings"
	"time"
	"unicode"
)

type SignalStatus string
type Severity string

const (
	StatusAvailable SignalStatus = "AVAILABLE"
	StatusMissing   SignalStatus = "MISSING"
	StatusError     SignalStatus = "ERROR"

	SeverityInfo   Severity = "INFO"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"

	ReasonMassJobOffer       = "MASS_JOB_OFFER"
	ReasonAdvertisingChannel = "ADVERTISING_CHANNEL"
	ReasonAdultContent       = "ADULT_CONTENT"
	ReasonNoPersonalChannel  = "NO_PERSONAL_CHANNEL"
	ReasonProfileFetchFailed = "PROFILE_FETCH_FAILED"
	ReasonNoSender           = "NO_SENDER"
)

// Signal is the versioned output shared by detection rules.
type Signal struct {
	SchemaVersion    string
	Detector         string
	DetectorVersion  string
	Category         string
	Status           SignalStatus
	Score            *float64
	Confidence       *float64
	Severity         Severity
	EvidenceCoverage float64
	ReasonCodes      []string
	MatchedRules     []string
	CreatedAt        time.Time
}

// Profile contains optional Telegram profile context.
type Profile struct {
	Username        string
	Bio             string
	PersonalChannel *PersonalChannel
}

// PersonalChannel contains the small profile-channel sample used by the rule.
type PersonalChannel struct {
	Title       string
	Username    string
	Description string
	RecentPosts []string
}

// ProfileDetector detects advertising hidden in a user's personal channel.
type ProfileDetector struct {
	now func() time.Time
}

// NewProfileDetector creates the current deterministic profile rule set.
func NewProfileDetector() *ProfileDetector {
	return newProfileDetector(time.Now)
}

func newProfileDetector(now func() time.Time) *ProfileDetector {
	return &ProfileDetector{now: now}
}

// Analyze returns review-oriented risk; it never performs a moderation action.
func (d *ProfileDetector) Analyze(profile Profile) Signal {
	base := Signal{
		SchemaVersion:   "1",
		Detector:        "profile.personal_channel",
		DetectorVersion: "profile-v3",
		Category:        "spam.profile",
		ReasonCodes:     []string{},
		MatchedRules:    []string{},
		CreatedAt:       d.now().UTC(),
	}
	if profile.PersonalChannel == nil && strings.TrimSpace(profile.Bio) == "" {
		base.Status = StatusMissing
		base.Severity = SeverityInfo
		base.ReasonCodes = []string{ReasonNoPersonalChannel}
		return base
	}

	parts := []string{profile.Username, profile.Bio}
	if profile.PersonalChannel != nil {
		channel := profile.PersonalChannel
		parts = append(parts, channel.Title, channel.Username, channel.Description)
		parts = append(parts, channel.RecentPosts...)
	}
	combinedText := strings.Join(parts, " ")
	text := normalize(combinedText)
	rawText := strings.ToLower(combinedText)

	massRecruitment := containsAny(text,
		"нужны сотрудники",
		"требуются сотрудники",
		"ищу сотрудников",
		"ищем сотрудников",
		"набор сотрудников",
		"набираем команду",
		"ищу людей",
		"ищем людей",
	)
	employmentHook := containsAny(text,
		"частичная занятость",
		"частичную занятость",
		"удаленная работа",
		"работа из дома",
		"свободный график",
		"подработка",
	)
	moneyHook := containsAny(text,
		"высокий доход",
		"стабильный доход",
		"заработок",
		"без вложений",
		"в день",
	)
	callToAction := containsAny(text,
		"пиши в личку",
		"пишите в личку",
		"пиши в лс",
		"пишите в лс",
		"подробности в лич",
	)

	score := 0.0
	reasons := []string{}
	rules := []string{}
	if massRecruitment {
		score = 0.75
		reasons = append(reasons, ReasonMassJobOffer, ReasonAdvertisingChannel)
		rules = append(rules, "PROFILE_JOB_01")
	}
	if massRecruitment && employmentHook {
		score += 0.17
		rules = append(rules, "PROFILE_JOB_02")
	}
	if massRecruitment && moneyHook {
		score += 0.08
		rules = append(rules, "PROFILE_JOB_03")
	}
	if massRecruitment && callToAction {
		score += 0.05
		rules = append(rules, "PROFILE_JOB_04")
	}

	strongAdult := containsAny(text,
		"onlyfans",
		"онлифанс",
		"нюдсы",
		"интимные фото",
		"интим фото",
		"интимные видео",
		"интим видео",
		"секс чат",
		"вебкам",
		"webcam",
		"порно канал",
	) || containsToken(text, "xxx")
	genericAdult := containsAny(text, "порно", "porn", "эротик", "adult content")
	adultPromotion := containsAny(text,
		"подписывайся",
		"подпишись",
		"subscribe",
		"приватный контент",
		"private content",
		"эксклюзивные фото",
		"эксклюзивные видео",
		"доступ в канал",
		"смотреть видео",
	)
	ageMarker := strings.Contains(rawText, "18+") || strings.Contains(rawText, "🔞")
	adultScore := 0.0
	adultRule := ""
	if strongAdult {
		adultScore = 0.95
		adultRule = "PROFILE_ADULT_01"
	} else if (genericAdult || ageMarker) && adultPromotion {
		adultScore = 0.93
		adultRule = "PROFILE_ADULT_02"
	}
	if adultScore > 0 {
		if adultScore > score {
			score = adultScore
		}
		reasons = appendUnique(reasons, ReasonAdultContent, ReasonAdvertisingChannel)
		rules = append(rules, adultRule)
	}
	profileHasLink := containsAny(rawText, "http://", "https://", "t.me/", "telegram.me/")
	commercialScore, commercialReasons, commercialRules := detectCommercialPromotion(
		combinedText,
		profileHasLink,
		"PROFILE_AD_",
	)
	if commercialScore > 0 {
		if commercialScore > score {
			score = commercialScore
		}
		reasons = appendUnique(reasons, commercialReasons...)
		if profile.PersonalChannel != nil {
			reasons = appendUnique(reasons, ReasonAdvertisingChannel)
		}
		rules = append(rules, commercialRules...)
	}
	if score > 1 {
		score = 1
	}

	confidence := 0.95
	base.Status = StatusAvailable
	base.Score = &score
	base.Confidence = &confidence
	base.Severity = severityFor(score)
	base.EvidenceCoverage = profileCoverage(profile)
	base.ReasonCodes = reasons
	base.MatchedRules = rules
	return base
}

func appendUnique(values []string, additions ...string) []string {
	for _, addition := range additions {
		if !containsString(values, addition) {
			values = append(values, addition)
		}
	}
	return values
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func normalize(value string) string {
	value = strings.ToLower(strings.ReplaceAll(value, "ё", "е"))
	return strings.Join(strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}), " ")
}

func containsAny(value string, phrases ...string) bool {
	for _, phrase := range phrases {
		if strings.Contains(value, phrase) {
			return true
		}
	}
	return false
}

func containsToken(value, token string) bool {
	for _, field := range strings.Fields(value) {
		if field == token {
			return true
		}
	}
	return false
}

func severityFor(score float64) Severity {
	if score >= 0.9 {
		return SeverityHigh
	}
	if score >= 0.7 {
		return SeverityMedium
	}
	return SeverityInfo
}

func profileCoverage(profile Profile) float64 {
	available := 0
	if profile.Username != "" || profile.Bio != "" {
		available++
	}
	if profile.PersonalChannel != nil {
		available++
		if profile.PersonalChannel.Title != "" ||
			profile.PersonalChannel.Username != "" ||
			profile.PersonalChannel.Description != "" {
			available++
		}
		if len(profile.PersonalChannel.RecentPosts) > 0 {
			available++
		}
	}
	return float64(available) / 4
}
