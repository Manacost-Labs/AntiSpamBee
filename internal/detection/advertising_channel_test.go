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

func TestAdvertisingChannelDetectorConfirmsAdultPromotionFromChannelContext(t *testing.T) {
	post := "😘 Горячие ролики. Доступ по заявке в канал 👉 https://t.me/+exampleInvite"
	for _, tc := range []struct {
		name      string
		channel   PersonalChannel
		wantAdult bool
	}{
		{"screenshot", PersonalChannel{Title: "✨ Закрытый коллекция 18+", RecentPosts: []string{post}}, true},
		{"spaced age label", PersonalChannel{Title: "Коллекция 18 +", RecentPosts: []string{post}}, true},
		{"unicode age label", PersonalChannel{Title: "Коллекция １８＋", RecentPosts: []string{post}}, true},
		{"nonbreaking age space", PersonalChannel{Title: "Коллекция 18\u00a0+", RecentPosts: []string{post}}, true},
		{"adult description", PersonalChannel{Title: "Коллекция", Description: "Закрытая коллекция 18+", RecentPosts: []string{post}}, true},
		{"adult caption", PersonalChannel{RecentPosts: []string{"Горячие ролики 18+. Доступ по заявке https://t.me/+exampleInvite"}}, true},
		{"explicit adult promotion", PersonalChannel{RecentPosts: []string{"Интимные видео, доступ в канал https://t.me/+exampleInvite"}}, true},
		{"ordinary music marked 18+", PersonalChannel{Title: "Музыка 18+", RecentPosts: []string{"Мой новый альбом. Слушайте https://example.com"}}, false},
		{"news linking to a report", PersonalChannel{Title: "Технологии", RecentPosts: []string{"Интимные видео украли у пользователей — новость https://news.example.com"}}, false},
		{"music promotion with XXX title", PersonalChannel{Title: "Музыка", RecentPosts: []string{"XXX — мой новый альбом. Подписывайся https://music.example.com"}}, false},
		{"adult-labeled music platform", PersonalChannel{Title: "Мой блог 18+", RecentPosts: []string{"OnlyFans 18+ — мой музыкальный блог. Подпишись https://music.example.com"}}, false},
		{"women performing in music marked 18+", PersonalChannel{Title: "Музыка 18+", RecentPosts: []string{"Девушки выступают на концерте 18+. В нашем канале видео https://music.example.com"}}, false},
		{"title alone", PersonalChannel{Title: "Закрытая коллекция 18+"}, false},
		{"link alone", PersonalChannel{Title: "Закрытая коллекция 18+", RecentPosts: []string{"Мой канал https://t.me/+exampleInvite"}}, false},
		{"no adult context", PersonalChannel{Title: "Личный канал", RecentPosts: []string{post}}, false},
		{"no contact link", PersonalChannel{Title: "Коллекция 18+", RecentPosts: []string{"Горячие ролики. Доступ по заявке в канал"}}, false},
		{"no invitation", PersonalChannel{Title: "Коллекция 18+", RecentPosts: []string{"Горячие ролики https://example.com"}}, false},
		{"mixed personal posts", PersonalChannel{Title: "18+", RecentPosts: []string{post, "Новая песня и мои фотографии"}}, false},
		{"unknown media", PersonalChannel{Title: "18+", RecentPosts: []string{post, ""}}, false},
		{"personal description", PersonalChannel{Title: "18+", Description: "Мой дневник о музыке", RecentPosts: []string{post}}, false},
		{"warning in post", PersonalChannel{Title: "18+", RecentPosts: []string{"Это спам, не переходите по ссылке! " + post}}, false},
		{"warning in title", PersonalChannel{Title: "Разбор рекламы 18+", RecentPosts: []string{post}}, false},
		{"warning in description", PersonalChannel{Title: "18+", Description: "Пример спама 18+, не переходите по ссылке", RecentPosts: []string{post}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := NewAdvertisingChannelDetector().Analyze(Profile{PersonalChannel: &tc.channel})
			adult := signal.Score != nil && *signal.Score >= .98 && signal.Confidence != nil && *signal.Confidence >= .98 &&
				slices.Contains(signal.ReasonCodes, ReasonConfirmedAdultAdvertisingChannel)
			if adult != tc.wantAdult {
				t.Fatalf("adult = %v, want %v; signal = %+v", adult, tc.wantAdult, signal)
			}
		})
	}
}
