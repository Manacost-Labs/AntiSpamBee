package detection

import (
	"slices"
	"testing"
)

func TestMessageAdDetectorSandromaniaExamples(t *testing.T) {
	for _, tc := range []struct{ id, text string }{
		{"54127", "Сделаю: сайт, приложения, тг бота Все в лс"},
		{"54124", "Ищу траффера пишите в лс"},
		{"54109", "Дам ворк 500-800$ в день, закладки кидать не надо"},
		{"54060", "Скупаю акки плеерка с отзывами писать в лс"},
		{"54040", "Дам ворк 500-800$, не закладки и тд"},
		{"54008", "Купите у меня гпт плюс"},
		{"53967", "Возьму МТС Айди 14$ любое гео @ybifu"},
		{"53915", "6$ гк мтс физ срочно хаб авто бью сам"},
		{"53825", "Куплю акк плеерка минимум 100 отзывов писать в лс"},
	} {
		for _, kind := range []string{"text", "caption", "ocr"} {
			t.Run(tc.id+"/"+kind, func(t *testing.T) {
				content := MessageContent{}
				switch kind {
				case "text":
					content.Text = tc.text
				case "caption":
					content.Caption = tc.text
				case "ocr":
					content.OCRText = tc.text
				}
				signal := NewMessageAdDetector().Analyze(content)
				if signal.Score == nil || *signal.Score < .9 || signal.Confidence == nil || *signal.Confidence < .9 ||
					signal.EvidenceCoverage < .5 || !slices.Contains(signal.ReasonCodes, ReasonCommercialPromotion) {
					t.Fatalf("advertising example was not actionable: %+v", signal)
				}
			})
		}
	}
}

func TestCompactOffersDoNotFlagQuestionsOrDiscussion(t *testing.T) {
	for _, text := range []string{
		"Кто может сделать сайт? Напишите в лс",
		"Сделаю сайт для своего проекта",
		"Мне сделают сайт, обсуждаем приложения и ботов в лс",
		"Ищу работу траффером, пишите в лс",
		"Что значит траффер?",
		"На плеерке у меня аккаунт с сотней отзывов",
		"Не куплю акк плеерка, лучше заведу свой",
		"Где купить GPT Plus?",
		"Кто продает гпт плюс? Пишите в лс",
		"GPT Plus стоит 20$ в месяц",
		"Мой тариф МТС стоит 6$, физическая симка",
		"Кто пишет «Дам ворк 500-800$»?",
		"Мне написали: Купите у меня гпт плюс",
		"Осторожно мошенники! Дам ворк 500-800$ в день",
		"Разбор рекламы: Скупаю акки плеерка с отзывами писать в лс",
	} {
		t.Run(text, func(t *testing.T) {
			signal := NewMessageAdDetector().Analyze(MessageContent{Text: text})
			if signal.Score != nil && *signal.Score >= .9 && signal.EvidenceCoverage >= .5 {
				t.Fatalf("discussion must not authorize deletion: %+v", signal)
			}
		})
	}
}
