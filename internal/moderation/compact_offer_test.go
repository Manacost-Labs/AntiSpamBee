package moderation

import (
	"context"
	"fmt"
	"testing"

	"antispambee/internal/detection"
)

func TestProcessorDeletesCompactOffersWithoutBanning(t *testing.T) {
	for _, text := range []string{
		"Сделаю: сайт, приложения, тг бота Все в лс",
		"Ищу траффера пишите в лс",
		"Дам ворк 500-800$, не закладки и тд",
		"Куплю акк плеерка минимум 100 отзывов писать в лс",
		"Купите у меня гпт плюс",
		"Возьму МТС Айди 14$ любое гео @ybifu",
		"6$ гк мтс физ срочно хаб авто бью сам",
	} {
		for _, status := range []string{"member", "administrator"} {
			t.Run(text+"/"+status, func(t *testing.T) {
				store := &recordingStore{}
				processor, err := NewProcessor(store, &profileFetcherStub{memberStatus: status}, detection.NewProfileDetector(),
					WithPolicyStore(&communityPolicyStub{policy: CommunityPolicy{
						ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true, ModeratorChatID: -1002,
					}}))
				if err != nil {
					t.Fatal(err)
				}
				payload := fmt.Sprintf(`{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},"text":%q}}`, text)
				if err := processor.Process(context.Background(), telegramEvent(payload)); err != nil {
					t.Fatal(err)
				}
				if hasAction(store.outcome, ActionDeleteMessage) != (status == "member") || hasAction(store.outcome, ActionBanUser) {
					t.Fatalf("unexpected actions: %+v", store.outcome)
				}
				if status == "member" && (store.outcome.Evidence == nil || len(store.outcome.Actions) != 1 || len(store.outcome.Actions[0].Notification.Reasons) == 0) {
					t.Fatalf("missing evidence or deletion reason: %+v", store.outcome)
				}
			})
		}
	}
}
