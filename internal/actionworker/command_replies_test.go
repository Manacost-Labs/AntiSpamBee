package actionworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
)

func TestWorkerCommandReplyDelivery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		attempts int
		status   string
		delay    time.Duration
	}{
		{"success", nil, 1, "SENT", 0},
		{"network retry", errors.New("network unavailable"), 1, "RETRYABLE", time.Second},
		{"rate limit", &telegramapi.APIError{ErrorCode: 429, RetryAfter: 20 * time.Second}, 2, "RETRYABLE", 20 * time.Second},
		{"permanent failure", &telegramapi.APIError{ErrorCode: 403}, 1, "FAILED", 0},
		{"attempt limit", errors.New("network unavailable"), 5, "FAILED", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &repositoryStub{commandReplyFound: true, commandReply: moderation.ClaimedCommandReply{ReplyID: "reply-1", Attempts: tc.attempts, Reply: moderation.CommandReply{ChatID: -1001, Text: "Уровень защиты установлен: STRICT"}}}
			tg := &telegramStub{sendMessageErr: tc.err}
			worker := newTestWorker(t, repo, tg)
			now := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
			worker.now = func() time.Time { return now }
			worked, err := worker.RunOnce(context.Background())
			if err != nil || !worked || repo.commandReplyStatus != tc.status || len(tg.messages) != 1 || tg.messageChats[0] != -1001 {
				t.Fatalf("worked=%v err=%v repo=%+v telegram=%+v", worked, err, repo, tg)
			}
			if tc.delay > 0 && !repo.commandReplyNext.Equal(worker.now().UTC().Add(tc.delay)) {
				t.Fatalf("retry time=%v", repo.commandReplyNext)
			}
			if repo.policyCalls != 0 || tg.bans+tg.messageDeletes+tg.mutes+tg.unbans != 0 {
				t.Fatal("reply delivery must not execute command effects")
			}
		})
	}
}

func TestWorkerDoesNotCompleteReplyIfSendContextCancelled(t *testing.T) {
	repo := &repositoryStub{commandReplyFound: true, commandReply: moderation.ClaimedCommandReply{Attempts: 1, Reply: moderation.CommandReply{ChatID: 1, Text: "queued"}}}
	tg := &telegramStub{sendMessageErr: context.Canceled}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newTestWorker(t, repo, tg).RunOnce(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("RunOnce()=%v", err)
	}
	if repo.commandReplyStatus != "" {
		t.Fatal("cancelled send must leave the lease recoverable")
	}
}

type reviewRepositoryStub struct{ repositoryStub }

func (*reviewRepositoryStub) PendingReviewForModerator(context.Context, string, string, int64) (moderation.ReviewCase, bool, error) {
	return moderation.ReviewCase{Target: moderation.ActionTarget{ChatID: -1001}}, true, nil
}

type reviewTelegramStub struct {
	telegramStub
	buttons []telegramapi.CallbackButton
}

func (tg *reviewTelegramStub) SendMessageWithCallbackButtons(_ context.Context, _ int64, _ string, buttons []telegramapi.CallbackButton) error {
	tg.buttons = buttons
	return nil
}

func TestReviewDeliveryChecksCurrentAdministratorAndAttachesButtons(t *testing.T) {
	const reviewID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	for _, status := range []string{"administrator", "member"} {
		t.Run(status, func(t *testing.T) {
			repo := &reviewRepositoryStub{repositoryStub: repositoryStub{commandReplyFound: true, commandReply: moderation.ClaimedCommandReply{
				Attempts: 1, Reply: moderation.CommandReply{ChatID: 91, Text: "На проверку", ReviewEventID: reviewID},
			}}}
			tg := &reviewTelegramStub{telegramStub: telegramStub{memberStatus: status}}
			worker, err := New(repo, tg, "review-test")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := worker.RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if status == "member" {
				if len(tg.buttons) != 0 || repo.commandReplyStatus != "FAILED" {
					t.Fatal("review was delivered after losing admin status")
				}
				return
			}
			if len(tg.buttons) != 2 || tg.buttons[0].Data != "review:keep:"+reviewID || tg.buttons[1].Data != "review:spam:"+reviewID || repo.commandReplyStatus != "SENT" {
				t.Fatalf("buttons=%+v status=%s", tg.buttons, repo.commandReplyStatus)
			}
		})
	}
}
