package moderation

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"antispambee/internal/detection"
)

func TestProcessorModeratesRecruitmentAndDocumentSpam(t *testing.T) {
	const delivery = "Нужны люди для доставки заказов\nОплата 13 000 рублей за смену\nМожно без опыта\nНачать можно уже сегодня\nИнтересны детали? @example"
	const documents = "Помогаем получить Официально Высшее и Среднее образование всего за 1-3 месяца! 🎓 Помощь при поступлении и сдаче сессий! Переводы, Заверение, Апостиль и Легализация документов. 📘 Подписывайся! https://example.com"
	const educationTitle = "Высшее и среднее образование 1-2 месяца"
	for _, tc := range []struct {
		name, text, mode, memberStatus string
		channel                        *detection.PersonalChannel
		want                           ActionType
		wantSemantic                   bool
	}{
		{name: "delivery post", text: delivery, want: ActionDeleteMessage},
		{name: "driver post", text: "Привет, ищу водителя с личным авто желательно, но могу рассмотреть только с правами\nРейс от 10 000 и больше\nЕсть аванс и компенсация расходов", want: ActionDeleteMessage},
		{name: "payout post", text: "Всем привет, появилась возможность взять 2 ребят, получите по 5600", want: ActionDeleteMessage},
		{name: "message 61713", text: "Приветствую, нужно будет помочь забрать вещи со съемной квартиры, каждому получится 6000", want: ActionDeleteMessage},
		{name: "apartment pickup without a payout", text: "Всем привет, кто может помочь забрать вещи со съёмной квартиры на выходных?", want: ActionAllow, wantSemantic: true},
		{name: "apartment deposit split", text: "Съезжаем со съёмной квартиры, делим залог пополам. Каждому получится 6000.", want: ActionAllow, wantSemantic: true},
		{name: "education post", text: documents, want: ActionDeleteMessage},
		{name: "education channel", text: "Жду новые карты в Стандарте", channel: &detection.PersonalChannel{Title: educationTitle, RecentPosts: []string{documents}}, want: ActionDeleteMessage},
		{name: "education channel media without text", channel: &detection.PersonalChannel{Title: educationTitle, RecentPosts: []string{documents}}, want: ActionDeleteMessage},
		{name: "education channel standard mode", text: "Жду новые карты в Стандарте", channel: &detection.PersonalChannel{Title: educationTitle, RecentPosts: []string{documents}}, mode: "STANDARD", want: ActionReview, wantSemantic: true},
		{name: "education channel title alone", text: "Жду новые карты в Стандарте", channel: &detection.PersonalChannel{Title: educationTitle}, want: ActionAllow, wantSemantic: true},
		{name: "education discussion", text: "Можно ли получить высшее образование за 3 месяца? Поделитесь опытом.", want: ActionAllow, wantSemantic: true},
		{name: "education consulting", text: "Помогаем поступить и перевести образовательные документы. Консультация за 2 дня, пишите в личку.", want: ActionAllow, wantSemantic: true},
		{name: "education archive", text: "Помогаем получить образовательные документы за 2 месяца из архива. Пишите в личку.", want: ActionAllow, wantSemantic: true},
		{name: "discussing diplomas for sale", text: "Что такое диплом на заказ? Нашёл статью https://example.com", want: ActionAllow, wantSemantic: true},
		{name: "discussing courier pay", text: "Слышал, курьеры получают 13 000 рублей за смену. Кто-нибудь пробовал?", want: ActionAllow, wantSemantic: true},
		{name: "asking for a ride", text: "Ищу водителя с личным авто на выходные. Могу компенсировать расходы, пишите в лс.", want: ActionAllow, wantSemantic: true},
		{name: "payout discussion", text: "Вы правда получите по 5600 за участие в турнире?", want: ActionAllow, wantSemantic: true},
		{name: "quoted spam", text: "Мне прислали такой спам: " + delivery, want: ActionReview, wantSemantic: true},
		{name: "administrator protected", text: delivery, memberStatus: "administrator", want: ActionReview},
		{name: "observe mode", text: delivery, mode: "OBSERVE", want: ActionReview},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &recordingStore{}
			model := &semanticAdStub{signal: detection.Signal{Detector: "model.test"}}
			mode := tc.mode
			if mode == "" {
				mode = "STRICT"
			}
			processor, err := NewProcessor(store, &profileFetcherStub{
				profile: detection.Profile{PersonalChannel: tc.channel}, memberStatus: tc.memberStatus,
			}, detection.NewProfileDetector(), WithSemanticAnalyzer(model), WithPolicyStore(&communityPolicyStub{policy: CommunityPolicy{
				ProtectionLevel: mode, AutomaticActionsEnabled: true, AutobanEnabled: true,
			}}))
			if err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf(`{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":%q}}`, tc.text)
			if err := processor.Process(context.Background(), telegramEvent(payload)); err != nil {
				t.Fatal(err)
			}
			if got := store.outcome.Decision.AuthorizedAction; got != tc.want {
				t.Errorf("authorized action = %s, want %s", got, tc.want)
			}
			usedModel := slices.ContainsFunc(store.outcome.Signals, func(signal detection.Signal) bool {
				return signal.Detector == model.signal.Detector
			})
			if usedModel != tc.wantSemantic {
				t.Errorf("called semantic analyzer = %t, want %t", usedModel, tc.wantSemantic)
			}
			if tc.want == ActionDeleteMessage {
				if len(store.outcome.Actions) != 1 || !hasAction(store.outcome, ActionDeleteMessage) {
					t.Errorf("queued actions = %+v, want one deletion", store.outcome.Actions)
				}
			} else if len(store.outcome.Actions) != 0 {
				t.Errorf("queued actions = %+v, want none", store.outcome.Actions)
			}
		})
	}
}
