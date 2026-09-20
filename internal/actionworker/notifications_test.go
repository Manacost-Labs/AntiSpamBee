package actionworker

import (
	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
	"context"
	"testing"
	"time"
)

func TestOutboxRetriesNotificationWithoutDeletingAgain(t *testing.T) {
	repo := &repositoryStub{notificationFound: true, notification: moderation.ClaimedNotification{
		Attempts: 1, CommunityChatID: -1001, Payload: moderation.DeletionNotification{ChatID: 9, Message: "saved evidence"},
	}}
	tg := &telegramStub{memberStatus: "administrator", sendMessageErr: &telegramapi.APIError{ErrorCode: 429, RetryAfter: time.Minute}}
	w := newTestWorker(t, repo, tg)
	w.now = func() time.Time { return time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC) }
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.notificationStatus != "RETRYABLE" || repo.notificationNext.Sub(w.now()) != time.Minute || tg.messageDeletes != 0 {
		t.Fatalf("repo=%+v deletes=%d", repo, tg.messageDeletes)
	}
	tg.sendMessageErr = nil
	repo.notification.Attempts++
	if _, err := w.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.notificationStatus != "SENT" || tg.messageDeletes != 0 {
		t.Fatalf("status=%s deletes=%d", repo.notificationStatus, tg.messageDeletes)
	}
}

func TestOutboxDoesNotDiscloseEvidenceToFormerAdmin(t *testing.T) {
	repo := &repositoryStub{notificationFound: true, notification: moderation.ClaimedNotification{Attempts: 1, CommunityChatID: -1001, Payload: moderation.DeletionNotification{ChatID: 9, Message: "private"}}}
	tg := &telegramStub{memberStatus: "member"}
	if _, err := newTestWorker(t, repo, tg).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.notificationStatus != "CANCELLED" || len(tg.messages) != 0 {
		t.Fatalf("status=%s messages=%v", repo.notificationStatus, tg.messages)
	}
}
