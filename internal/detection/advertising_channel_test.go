package detection

import (
	"slices"
	"testing"
)

const recruitmentChannelPost = `Нужны сотрудники на частичную занятость (час/два в день).
Вакансия: Хеш-фаундер (без вложений)
Требования: Доступ к интернету. Усидчивость и внимательность.
Условия: Оплата: 8 000 рублей за объем работы.
Время выполнения: 4–6 часов (можно распределить по часу в день).
Работа полностью легальная. Вложений, паспортных данных и специальных программ не требуется.
За подробностями, пишите Евгению.
Пост размещен на правах рекламы.`

func TestAdvertisingChannelDetectorRequiresCompleteOffersInEveryPost(t *testing.T) {
	for _, tc := range []struct {
		name          string
		channel       *PersonalChannel
		wantConfirmed bool
	}{
		{"screenshot recruitment channel", &PersonalChannel{Title: "What??", RecentPosts: []string{recruitmentChannelPost}}, true},
		{"several recruitment posts", &PersonalChannel{RecentPosts: []string{recruitmentChannelPost, recruitmentChannelPost}}, true},
		{"gambling promotion", &PersonalChannel{RecentPosts: []string{"Казино: бонус за первый депозит. Регистрируйся https://example.com"}}, true},
		{"promotional description and post", &PersonalChannel{Description: recruitmentChannelPost, RecentPosts: []string{recruitmentChannelPost}}, true},
		{"no channel", nil, false},
		{"only channel metadata", &PersonalChannel{Title: "Free money", Description: recruitmentChannelPost}, false},
		{"truncated recruitment", &PersonalChannel{RecentPosts: []string{"Нужны сотрудники на частичную занятость"}}, false},
		{"no payment amount", &PersonalChannel{RecentPosts: []string{"Нужны сотрудники на частичную занятость, заработок без вложений. Пишите в личку."}}, false},
		{"personal music", &PersonalChannel{Title: "XXX", RecentPosts: []string{"Мой новый альбом, слушайте https://example.com"}}, false},
		{"music with sponsored post", &PersonalChannel{RecentPosts: []string{"Мои любимые песни", recruitmentChannelPost}}, false},
		{"music with sponsored post first", &PersonalChannel{RecentPosts: []string{recruitmentChannelPost, "Мои любимые песни"}}, false},
		{"media only and sponsored post", &PersonalChannel{RecentPosts: []string{recruitmentChannelPost, ""}}, false},
		{"personal description and sponsored post", &PersonalChannel{Description: "Мой канал о музыке", RecentPosts: []string{recruitmentChannelPost}}, false},
		{"warning with quoted advertisement", &PersonalChannel{RecentPosts: []string{"Осторожно мошенники, не переходите по ссылке! " + recruitmentChannelPost}}, false},
		{"separate fragments", &PersonalChannel{RecentPosts: []string{"Нужны сотрудники на частичную занятость", "Без вложений, оплата 8 000 рублей. Пишите в личку."}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := NewAdvertisingChannelDetector().Analyze(Profile{
				Username: "job_money", Bio: recruitmentChannelPost, PersonalChannel: tc.channel,
			})
			confirmed := signal.Score != nil && *signal.Score >= .9 && signal.EvidenceCoverage >= .5
			if confirmed != tc.wantConfirmed {
				t.Fatalf("confirmed = %v, want %v; signal = %+v", confirmed, tc.wantConfirmed, signal)
			}
			if confirmed && (signal.EvidenceExcerpt == "" || !slices.Contains(signal.ReasonCodes, ReasonConfirmedAdvertisingChannel)) {
				t.Fatalf("confirmed signal must explain the post: %+v", signal)
			}
		})
	}
}
