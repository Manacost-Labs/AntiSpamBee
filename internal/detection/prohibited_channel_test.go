package detection

import (
	"slices"
	"testing"
)

func TestProhibitedChannelEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		channel *PersonalChannel
		reason  string
	}{
		{"adult identity without posts", &PersonalChannel{Title: "Порно 18+"}, ReasonConfirmedAdultChannel},
		{"message 54888 uncensored secret funnel", &PersonalChannel{Title: "Мой секрет 😘", RecentPosts: []string{"🎥 Без цензуры и ограничений — заявка открывает доступ\n👉 https://t.me/+exampleInvite", "", ""}}, ReasonConfirmedAdultChannel},
		{"message 58872 private milf funnel", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"🔥ОПЫТНАЯ МАМОЧКА РАЗДЕЛАСЬ НА КАМЕРУ ТУТ👉https://t.me/+exampleInvite", ""}}, ReasonConfirmedAdultChannel},
		{"private milf funnel with joinchat", &PersonalChannel{Title: "Милфы | Приват", RecentPosts: []string{"Мамочка раздевается на камеру https://t.me/joinchat/exampleInvite"}}, ReasonConfirmedAdultChannel},
		{"adult description and captionless media", &PersonalChannel{Title: "Коллекция", Description: "Эротические фото и интимные видео", RecentPosts: []string{"", "", ""}}, ReasonConfirmedAdultChannel},
		{"adult post among ordinary posts", &PersonalChannel{RecentPosts: []string{"Доброе утро", "Порно видео каждый день", ""}}, ReasonConfirmedAdultChannel},
		{"adult post without an offer", &PersonalChannel{RecentPosts: []string{"Интимные фото и видео"}}, ReasonConfirmedAdultChannel},
		{"adult euphemistic identity", &PersonalChannel{Title: "Горячие девочки 18+", RecentPosts: []string{""}}, ReasonConfirmedAdultChannel},
		{"adult offer with channel context", &PersonalChannel{Title: "Коллекция 18+", RecentPosts: []string{"Горячие ролики. Доступ по заявке https://t.me/+invite", ""}}, ReasonConfirmedAdultChannel},
		{"guaranteed returns", &PersonalChannel{RecentPosts: []string{"Инвестиции: гарантированная прибыль без риска. Пишите в личку", "Новости", ""}}, ReasonConfirmedFraudChannel},
		{"deposit doubling in description", &PersonalChannel{Description: "Удвою твои деньги. Переведи депозит, пиши в лс"}, ReasonConfirmedFraudChannel},
		{"deposit scheme", &PersonalChannel{RecentPosts: []string{"Раскрутка депозита. Пишите https://t.me/example"}}, ReasonConfirmedFraudChannel},
		{"job fee", &PersonalChannel{RecentPosts: []string{"Удаленная работа: оплатите доступ к работе. Пишите в лс"}}, ReasonConfirmedFraudChannel},
		{"fake prize fee", &PersonalChannel{RecentPosts: []string{"Вы выиграли приз. Для получения выигрыша оплатите комиссию"}}, ReasonConfirmedFraudChannel},
		{"english scam", &PersonalChannel{RecentPosts: []string{"Guaranteed investment profit, risk-free. DM me"}}, ReasonConfirmedFraudChannel},
		{"no channel even with adult bio", nil, ""},
		{"empty channel", &PersonalChannel{}, ""},
		{"age marker only", &PersonalChannel{Title: "Личный блог 18+", RecentPosts: []string{""}}, ""},
		{"uncensored news channel", &PersonalChannel{Title: "Новости без цензуры", RecentPosts: []string{"Без цензуры и ограничений — заявка открывает доступ https://t.me/+exampleInvite"}}, ""},
		{"secret title alone", &PersonalChannel{Title: "Мой секрет 😘", RecentPosts: []string{"", "Доброе утро"}}, ""},
		{"private milf title alone", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"", "Доброе утро"}}, ""},
		{"private milf without sexual headline", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"Доброе утро https://t.me/+exampleInvite"}}, ""},
		{"private milf without invite", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"Мамочка разделась на камеру"}}, ""},
		{"private milf split post fragments", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"Мамочка разделась на камеру", "https://t.me/+exampleInvite"}}, ""},
		{"private mothers ordinary channel", &PersonalChannel{Title: "Приват мамочек", RecentPosts: []string{"Советы для молодых мам https://t.me/+exampleInvite"}}, ""},
		{"private unrelated name substring", &PersonalChannel{Title: "Приват Милфорд", RecentPosts: []string{"Актриса разделась на камеру https://t.me/+exampleInvite"}}, ""},
		{"private milf quoted warning", &PersonalChannel{Title: "Приват Милфы", RecentPosts: []string{"Не вступайте: мамочка разделась на камеру https://t.me/+exampleInvite"}}, ""},
		{"secret with ordinary public link", &PersonalChannel{Title: "Мой секрет 😘", RecentPosts: []string{"Без цензуры и ограничений — заявка открывает доступ https://example.com"}}, ""},
		{"secret without access solicitation", &PersonalChannel{Title: "Мой секрет 😘", RecentPosts: []string{"Мой текст без цензуры https://t.me/+exampleInvite"}}, ""},
		{"uncensored archive without suggestive identity", &PersonalChannel{Title: "Личный архив", RecentPosts: []string{"Без цензуры и ограничений — заявка открывает доступ https://t.me/+exampleInvite"}}, ""},
		{"music with platform name", &PersonalChannel{Title: "XXX", RecentPosts: []string{"OnlyFans 18+ — мой музыкальный блог. Подпишись https://music.example.com"}}, ""},
		{"ordinary job promotion", &PersonalChannel{RecentPosts: []string{recruitmentChannelPost}}, ""},
		{"ordinary investments", &PersonalChannel{RecentPosts: []string{"Инвестиции и криптовалюта. Риски, обзор рынка https://example.com"}}, ""},
		{"ordinary insured deposit", &PersonalChannel{RecentPosts: []string{"Вклад: гарантированный доход. Подробности https://example.com"}}, ""},
		{"split scam fragments", &PersonalChannel{RecentPosts: []string{"Гарантированная прибыль без риска", "Пишите в личку"}}, ""},
		{"quoted scam warning", &PersonalChannel{RecentPosts: []string{"Осторожно мошенники! Гарантированная прибыль без риска, пишите в лс"}}, ""},
		{"fraud education channel", &PersonalChannel{Description: "Разоблачение мошенников", RecentPosts: []string{"Удвою деньги, переведи депозит"}}, ""},
		{"sex education channel", &PersonalChannel{Description: "Сексуальное образование", RecentPosts: []string{"Порно и сексуальное здоровье"}}, ""},
		{"addiction discussion", &PersonalChannel{RecentPosts: []string{"Порно зависимость: как получить помощь"}}, ""},
		{"content disclaimer", &PersonalChannel{Description: "Мой канал без порно и без эротики"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signal := NewAdvertisingChannelDetector().AnalyzeProhibited(Profile{Bio: "Порно. Удвою деньги, пишите в лс", PersonalChannel: tc.channel})
			confirmed := signal.Score != nil && *signal.Score >= .98
			if confirmed != (tc.reason != "") {
				t.Fatalf("confirmed = %v, wanted reason %q; signal = %+v", confirmed, tc.reason, signal)
			}
			if tc.reason != "" && (!slices.Contains(signal.ReasonCodes, tc.reason) || signal.EvidenceExcerpt == "" || signal.EvidenceCoverage != 1 || *signal.Confidence < .98) {
				t.Fatalf("missing actionable evidence: %+v", signal)
			}
		})
	}
}
