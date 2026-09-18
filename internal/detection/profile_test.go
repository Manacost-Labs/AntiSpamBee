package detection

import (
	"slices"
	"testing"
	"time"
)

func TestProfileDetectorFlagsMassJobOfferInPersonalChannel(t *testing.T) {
	now := time.Date(2026, 9, 15, 19, 0, 0, 0, time.UTC)
	detector := newProfileDetector(func() time.Time { return now })

	signal := detector.Analyze(Profile{
		Username: "Kristinana04Alekseeva",
		Bio:      "Добрая, но не для всех",
		PersonalChannel: &PersonalChannel{
			Title:       "И там и здесь",
			Description: "Нужны сотрудники на частичную занятость. Пишите в личку.",
		},
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
	if !slices.Contains(signal.ReasonCodes, ReasonMassJobOffer) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonMassJobOffer)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonAdvertisingChannel) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonAdvertisingChannel)
	}
	if signal.CreatedAt != now {
		t.Errorf("created at = %s, want %s", signal.CreatedAt, now)
	}
}

func TestProfileDetectorFlagsRecruitmentAcrossRecentPosts(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			RecentPosts: []string{
				"Ищем людей в команду",
				"Удалённая работа, свободный график и высокий доход",
			},
		},
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
}

func TestProfileDetectorFlagsExactVisibleScreenshotPhrase(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			Description: "Нужны сотрудники на частичную занятость",
		},
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9 for screenshot phrase", signal.Score)
	}
}

func TestProfileDetectorFlagsAdultPersonalChannel(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			Title:       "Приватный канал 18+",
			Description: "Нюдсы и эксклюзивные интимные фото",
			RecentPosts: []string{"OnlyFans — private content, subscribe"},
		},
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
	if signal.Severity != SeverityHigh {
		t.Errorf("severity = %q, want HIGH", signal.Severity)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonAdultContent) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonAdultContent)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonAdvertisingChannel) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonAdvertisingChannel)
	}
}

func TestProfileDetectorFlagsPromotedPornChannel(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			Description: "Порно видео 18+. Подписывайся на канал",
		},
	})

	if signal.Score == nil || *signal.Score < 0.9 {
		t.Fatalf("score = %v, want at least 0.9", signal.Score)
	}
}

func TestProfileDetectorFlagsProhibitedAdsInBio(t *testing.T) {
	detector := newProfileDetector(time.Now)
	tests := []struct {
		name   string
		bio    string
		reason string
	}{
		{
			name:   "vpn",
			bio:    "Бесплатный VPN — установи сейчас: t.me/free_vpn",
			reason: ReasonVPNPromotion,
		},
		{
			name:   "gambling",
			bio:    "Казино и ставки. Бонус за депозит — забрать: t.me/win",
			reason: ReasonGamblingPromotion,
		},
		{
			name:   "crypto scam",
			bio:    "Крипта: гарантированная прибыль 20% без риска. Вступай: t.me/rich",
			reason: ReasonCryptoPromotion,
		},
		{
			name:   "payday loan",
			bio:    "Займ без отказа за 5 минут. Оформить: t.me/cash",
			reason: ReasonLoanPromotion,
		},
		{
			name:   "mass job offer",
			bio:    "Нужны сотрудники на частичную занятость. Пишите в личку",
			reason: ReasonMassJobOffer,
		},
		{
			name:   "adult channel",
			bio:    "Порно канал 18+. Подписывайся смотреть видео",
			reason: ReasonAdultContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signal := detector.Analyze(Profile{Bio: tt.bio})
			if signal.Score == nil || *signal.Score < 0.9 {
				t.Fatalf("score = %v, want at least 0.9", signal.Score)
			}
			if !slices.Contains(signal.ReasonCodes, tt.reason) {
				t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, tt.reason)
			}
		})
	}
}

func TestProfileDetectorDoesNotFlagNeutralSensitiveTopicsInBio(t *testing.T) {
	detector := newProfileDetector(time.Now)

	for _, bio := range []string{
		"Обсуждаю регулирование казино",
		"Изучаю блокчейн и инвестиции",
		"Закрыл кредит, пишу о личных финансах",
		"Ищу стабильный VPN для путешествий",
	} {
		signal := detector.Analyze(Profile{Bio: bio})
		if signal.Score == nil || *signal.Score != 0 {
			t.Errorf("bio %q: score = %v, want 0", bio, signal.Score)
		}
	}
}

func TestProfileDetectorDoesNotFlagNeutralAdultTopicMention(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			Title:       "Психология отношений",
			Description: "Исследование зависимости от порно и её влияния на отношения",
		},
	})

	if signal.Score == nil || *signal.Score != 0 {
		t.Fatalf("score = %v, want 0", signal.Score)
	}
	if slices.Contains(signal.ReasonCodes, ReasonAdultContent) {
		t.Errorf("reason codes = %v, do not want %q", signal.ReasonCodes, ReasonAdultContent)
	}
}

func TestProfileDetectorTreatsXXXAsAStandaloneMarker(t *testing.T) {
	detector := newProfileDetector(time.Now)

	suspicious := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{Description: "XXX видео для взрослых"},
	})
	if suspicious.Score == nil || *suspicious.Score < 0.9 {
		t.Fatalf("XXX channel score = %v, want at least 0.9", suspicious.Score)
	}

	ordinary := detector.Analyze(Profile{
		PersonalChannel: &PersonalChannel{
			Username:    "alexxxander",
			Description: "Личный блог о путешествиях",
		},
	})
	if ordinary.Score == nil || *ordinary.Score != 0 {
		t.Fatalf("ordinary channel score = %v, want 0", ordinary.Score)
	}
}

func TestProfileDetectorDoesNotFlagOrdinaryPersonalChannel(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{
		Username: "woodworker",
		Bio:      "Делаю мебель своими руками",
		PersonalChannel: &PersonalChannel{
			Title:       "Столярная мастерская",
			Description: "Про инструменты и работу с деревом",
			RecentPosts: []string{"Сегодня закончил дубовый стол"},
		},
	})

	if signal.Status != StatusAvailable {
		t.Fatalf("status = %q, want AVAILABLE", signal.Status)
	}
	if signal.Score == nil || *signal.Score != 0 {
		t.Fatalf("score = %v, want 0", signal.Score)
	}
	if signal.Severity != SeverityInfo {
		t.Errorf("severity = %q, want INFO", signal.Severity)
	}
}

func TestProfileDetectorReturnsMissingWithoutPersonalChannel(t *testing.T) {
	detector := newProfileDetector(time.Now)

	signal := detector.Analyze(Profile{Username: "ordinary_user"})

	if signal.Status != StatusMissing {
		t.Fatalf("status = %q, want MISSING", signal.Status)
	}
	if signal.Score != nil || signal.Confidence != nil {
		t.Fatalf("score = %v, confidence = %v; want nil", signal.Score, signal.Confidence)
	}
	if !slices.Contains(signal.ReasonCodes, ReasonNoPersonalChannel) {
		t.Errorf("reason codes = %v, want %q", signal.ReasonCodes, ReasonNoPersonalChannel)
	}
	if signal.MatchedRules == nil {
		t.Error("matched rules is nil, want an explicit empty list")
	}
}
