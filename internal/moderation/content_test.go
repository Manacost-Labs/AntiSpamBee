package moderation

import (
	"context"
	"testing"

	"antispambee/internal/detection"
)

type contentAnalyzerStub struct {
	input  detection.SemanticAdContent
	signal detection.Signal
}

func (analyzer *contentAnalyzerStub) AnalyzeContent(_ context.Context, input detection.SemanticAdContent) []detection.Signal {
	analyzer.input = input
	return []detection.Signal{analyzer.signal}
}

type imageDownloaderStub struct{ fileID string }

func (downloader *imageDownloaderStub) DownloadFile(_ context.Context, fileID string, _ int64) ([]byte, error) {
	downloader.fileID = fileID
	return []byte("image bytes"), nil
}

func TestProcessorAuthorizesSemanticContentBySource(t *testing.T) {
	for _, test := range []struct {
		name, source, mode, status, payload string
		want                                ActionType
	}{
		{"image", detection.SemanticMessageDetector, "STANDARD", "member", `"photo":[{"file_id":"photo-id"}]`, ActionDeleteMessage},
		{"profile strict", detection.SemanticProfileDetector, "STRICT", "member", `"text":"Хорошая карта"`, ActionDeleteMessage},
		{"profile image", detection.SemanticProfileDetector, "STRICT", "member", `"text":"Хорошая карта"`, ActionDeleteMessage},
		{"profile standard", detection.SemanticProfileDetector, "STANDARD", "member", `"text":"Хорошая карта"`, ActionReview},
		{"profile admin", detection.SemanticProfileDetector, "STRICT", "administrator", `"text":"Хорошая карта"`, ActionReview},
		{"outside configured chat", detection.SemanticMessageDetector, "STRICT", "member", `"text":"Хорошая карта"`, ActionAllow},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &recordingStore{}
			model := &contentAnalyzerStub{signal: availableSignal(test.source, .96, .96, 1)}
			model.signal.EvidenceExcerpt = "Явное предложение подписки за деньги"
			images := &imageDownloaderStub{}
			profile := detection.Profile{Bio: "Подписки на сервисы, пишите в личку"}
			if test.name == "profile image" {
				profile.PersonalChannel = &detection.PersonalChannel{
					Username: "public_channel", RecentPosts: []string{"", ""}, RecentPostImageIDs: []string{"", "profile-photo"},
				}
			}
			chatID := int64(-1001)
			if test.name == "outside configured chat" {
				chatID = -1002
			}
			processor, err := NewProcessor(store, &profileFetcherStub{
				profile: profile, memberStatus: test.status,
			}, detection.NewProfileDetector(), WithContentAnalyzer(model, images, chatID), WithPolicyStore(&communityPolicyStub{
				policy: CommunityPolicy{ProtectionLevel: test.mode, AutomaticActionsEnabled: true, AutobanEnabled: true},
			}))
			if err != nil {
				t.Fatal(err)
			}
			payload := `{"message":{"message_id":7,"from":{"id":42},"chat":{"id":-1001,"type":"supergroup"},` + test.payload + `}}`
			if err := processor.Process(context.Background(), telegramEvent(payload)); err != nil {
				t.Fatal(err)
			}
			if got := store.outcome.Decision.AuthorizedAction; got != test.want {
				t.Fatalf("action = %s, want %s (%s)", got, test.want, store.outcome.Decision.AuthorizationReason)
			}
			if test.name == "image" && (images.fileID != "photo-id" || len(model.input.Image) == 0) {
				t.Fatal("photo was not sent to classifier")
			}
			if test.name == "profile image" && (images.fileID != "profile-photo" || len(model.input.ProfileImages) != 1 || model.input.ProfileImages[0].PostNumber != 2) {
				t.Fatal("profile channel photo was not associated with its post")
			}
			if test.name == "outside configured chat" && model.input.Message.Text != "" {
				t.Fatal("sent content from another chat to the multimodal classifier")
			}
			if test.name == "profile strict" && store.outcome.Decision.AuthorizationReason != ReasonConfirmedProfileAdvertising {
				t.Fatalf("reason = %s", store.outcome.Decision.AuthorizationReason)
			}
			if hasAction(store.outcome, ActionBanUser) || hasAction(store.outcome, ActionDeleteMessage) != (test.want == ActionDeleteMessage) {
				t.Fatalf("unexpected actions: %+v", store.outcome.Actions)
			}
		})
	}
}
