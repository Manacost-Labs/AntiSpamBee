package actionworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
)

type repositoryStub struct {
	action       moderation.ClaimedAction
	found        bool
	claimErr     error
	succeeded    bool
	assumed      bool
	retryAt      time.Time
	retryError   string
	permanentErr string
}

func (r *repositoryStub) ClaimAction(context.Context, string, time.Duration) (moderation.ClaimedAction, bool, error) {
	return r.action, r.found, r.claimErr
}
func (r *repositoryStub) MarkActionSucceeded(_ context.Context, _ moderation.ClaimedAction, assumed bool) error {
	r.succeeded = true
	r.assumed = assumed
	return nil
}
func (r *repositoryStub) MarkActionRetryable(_ context.Context, _ moderation.ClaimedAction, next time.Time, message string) error {
	r.retryAt = next
	r.retryError = message
	return nil
}
func (r *repositoryStub) MarkActionPermanentFailure(_ context.Context, _ moderation.ClaimedAction, message string) error {
	r.permanentErr = message
	return nil
}

type telegramStub struct {
	banErr            error
	deleteMessageErr  error
	deleteReactionErr error
	memberStatus      string
	memberStatusErr   error
	bans              int
	messageDeletes    int
	reactionDeletes   int
	mutes             int
	unbans            int
}

func (t *telegramStub) BanChatMember(context.Context, int64, int64) error {
	t.bans++
	return t.banErr
}
func (t *telegramStub) DeleteMessage(context.Context, int64, int64) error {
	t.messageDeletes++
	return t.deleteMessageErr
}
func (t *telegramStub) DeleteMessageReaction(context.Context, int64, int64, int64) error {
	t.reactionDeletes++
	return t.deleteReactionErr
}
func (t *telegramStub) GetChatMemberStatus(context.Context, int64, int64) (string, error) {
	return t.memberStatus, t.memberStatusErr
}
func (t *telegramStub) RestrictChatMember(context.Context, int64, int64, int64) error {
	t.mutes++
	return nil
}
func (t *telegramStub) UnbanChatMember(context.Context, int64, int64) error {
	t.unbans++
	return nil
}

func TestWorkerExecutesDeleteReaction(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionDeleteReaction, 1)}
	telegram := &telegramStub{}
	worker := newTestWorker(t, repo, telegram)

	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("RunOnce() = %v, %v", worked, err)
	}
	if telegram.reactionDeletes != 1 || !repo.succeeded {
		t.Fatalf("reaction deletes = %d, succeeded = %v", telegram.reactionDeletes, repo.succeeded)
	}
}

func TestWorkerExecutesMute(t *testing.T) {
	action := claimedAction(moderation.ActionMuteUser, 1)
	action.UntilDate = 4102444800
	repo := &repositoryStub{found: true, action: action}
	telegram := &telegramStub{}
	worker := newTestWorker(t, repo, telegram)
	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked || telegram.mutes != 1 || !repo.succeeded {
		t.Fatalf("worked/error/mutes/succeeded = %v/%v/%d/%v", worked, err, telegram.mutes, repo.succeeded)
	}
}

func TestWorkerExecutesUnban(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionUnbanUser, 1)}
	telegram := &telegramStub{}
	worker := newTestWorker(t, repo, telegram)

	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked || telegram.unbans != 1 || !repo.succeeded {
		t.Fatalf("worked/error/unbans/succeeded = %v/%v/%d/%v", worked, err, telegram.unbans, repo.succeeded)
	}
}

func TestWorkerTreatsPreviouslyCompletedBanAsAssumedSuccess(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 2)}
	telegram := &telegramStub{memberStatus: "kicked"}
	worker := newTestWorker(t, repo, telegram)

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if telegram.bans != 0 || !repo.succeeded || !repo.assumed {
		t.Fatalf("bans = %d, succeeded/assumed = %v/%v", telegram.bans, repo.succeeded, repo.assumed)
	}
}

func TestWorkerHonorsTelegramRetryAfter(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionDeleteMessage, 1)}
	telegram := &telegramStub{deleteMessageErr: &telegramapi.APIError{
		ErrorCode: 429, Description: "Too Many Requests", RetryAfter: 17 * time.Second,
	}}
	worker := newTestWorker(t, repo, telegram)
	worker.now = func() time.Time { return now }

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !repo.retryAt.Equal(now.Add(17 * time.Second)) {
		t.Fatalf("retry at = %v", repo.retryAt)
	}
}

func TestWorkerDeadLettersPermanentTelegramFailure(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionDeleteMessage, 1)}
	telegram := &telegramStub{deleteMessageErr: &telegramapi.APIError{ErrorCode: 403, Description: "Forbidden"}}
	worker := newTestWorker(t, repo, telegram)

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if repo.permanentErr == "" || repo.retryError != "" {
		t.Fatalf("permanent/retry errors = %q/%q", repo.permanentErr, repo.retryError)
	}
}

func TestWorkerDeadLettersAfterRetryBudget(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionDeleteMessage, 5)}
	telegram := &telegramStub{deleteMessageErr: errors.New("connection reset")}
	worker := newTestWorker(t, repo, telegram)

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if repo.permanentErr == "" {
		t.Fatal("expected retry exhaustion to become permanent failure")
	}
}

func newTestWorker(t *testing.T, repo Repository, telegram TelegramClient) *Worker {
	t.Helper()
	worker, err := New(repo, telegram, "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

func claimedAction(action moderation.ActionType, attempt int) moderation.ClaimedAction {
	return moderation.ClaimedAction{
		ActionID: "action-1", EventID: "event-1", TenantID: "tenant-1",
		Type: action, AttemptCount: attempt,
		Target: moderation.ActionTarget{Kind: moderation.TargetMessage, ChatID: -1001, UserID: 42, MessageID: 7},
	}
}
