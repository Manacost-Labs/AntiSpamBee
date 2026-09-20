package detection

import "testing"

func TestWarningsAndQuotedAdsCannotEnforceByKeywordsAlone(t *testing.T) {
	for _, text := range []string{
		`Осторожно, мошенники! Ищем сотрудников, удаленная работа, 5000 рублей в день, пишите в лс`,
		`Мне прислали: «Ищем сотрудников, удаленная работа, 5000 рублей в день, пишите в лс». Это спам?`,
		`Не переходите по ссылке: бесплатный VPN, подключайся https://example.com`,
	} {
		signal := NewMessageAdDetector().Analyze(MessageContent{Text: text})
		if signal.Score != nil && *signal.Score >= .9 && signal.EvidenceCoverage >= .5 {
			t.Errorf("unsafe keyword evidence for %q", text)
		}
	}
}

func TestActivityAloneDoesNotIdentifyBot(t *testing.T) {
	signal := NewBehaviorDetector().Analyze(BehaviorStats{MessagesInWindow: 6})
	if signal.Score == nil || *signal.Score >= .9 {
		t.Fatal("ordinary active conversation assigned high spam risk")
	}
}
