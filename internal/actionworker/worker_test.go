package actionworker

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
)

type repositoryStub struct {
	action             moderation.ClaimedAction
	found              bool
	claimErr           error
	succeeded          bool
	assumed            bool
	retryAt            time.Time
	retryError         string
	permanentErr       string
	cancelledErr       string
	notification       moderation.ClaimedNotification
	notificationFound  bool
	notificationStatus string
	notificationNext   time.Time
	completionErr      error
	policy             *moderation.CommunityPolicy
	policyErr          error
	policyCalls        int
	commandReply       moderation.ClaimedCommandReply
	commandReplyFound  bool
	commandReplyStatus string
	commandReplyNext   time.Time
	commandReplyError  string
}

func (r *repositoryStub) ClaimCommandReply(context.Context, string, time.Duration) (moderation.ClaimedCommandReply, bool, error) {
	return r.commandReply, r.commandReplyFound, nil
}

func (r *repositoryStub) FinishCommandReply(_ context.Context, _ moderation.ClaimedCommandReply, status string, next time.Time, message string) error {
	if r.completionErr != nil {
		return r.completionErr
	}
	r.commandReplyStatus, r.commandReplyNext, r.commandReplyError = status, next, message
	r.commandReplyFound = status == "RETRYABLE"
	return nil
}

func (r *repositoryStub) GetCommunityPolicy(_ context.Context, tenantID string, chatID, userID int64) (moderation.CommunityPolicy, error) {
	r.policyCalls++
	if tenantID != r.action.TenantID || chatID != r.action.Target.ChatID || userID != r.action.Target.UserID {
		return moderation.CommunityPolicy{}, errors.New("incorrect policy lookup identity")
	}
	if r.policy != nil {
		return *r.policy, r.policyErr
	}
	return moderation.CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true}, r.policyErr
}

func (r *repositoryStub) ClaimAction(context.Context, string, time.Duration) (moderation.ClaimedAction, bool, error) {
	return r.action, r.found, r.claimErr
}
func (r *repositoryStub) MarkActionSucceeded(_ context.Context, _ moderation.ClaimedAction, assumed bool) error {
	if r.completionErr != nil {
		return r.completionErr
	}
	r.succeeded = true
	r.assumed = assumed
	if r.action.Type == moderation.ActionDeleteMessage && r.action.Notification.ChatID > 0 {
		r.notification = moderation.ClaimedNotification{ActionID: r.action.ActionID, CommunityChatID: r.action.Target.ChatID, Payload: r.action.Notification, Attempts: 1}
		r.notificationFound = true
	}
	return nil
}
func (r *repositoryStub) ClaimNotification(context.Context, string, time.Duration) (moderation.ClaimedNotification, bool, error) {
	return r.notification, r.notificationFound, nil
}
func (r *repositoryStub) FinishNotification(_ context.Context, _ moderation.ClaimedNotification, status string, next time.Time, _ string) error {
	r.notificationStatus = status
	r.notificationNext = next
	return nil
}
func (r *repositoryStub) NotificationRecipientCurrent(context.Context, moderation.ClaimedNotification) (bool, error) {
	return true, nil
}
func (r *repositoryStub) PurgeExpiredEvidence(context.Context) error { return nil }
func (r *repositoryStub) MarkActionRetryable(_ context.Context, _ moderation.ClaimedAction, next time.Time, message string) error {
	r.retryAt = next
	r.retryError = message
	return nil
}
func (r *repositoryStub) MarkActionPermanentFailure(_ context.Context, _ moderation.ClaimedAction, message string) error {
	r.permanentErr = message
	return nil
}

func (r *repositoryStub) MarkActionCancelled(_ context.Context, _ moderation.ClaimedAction, message string) error {
	r.cancelledErr = message
	return nil
}

type telegramStub struct {
	banErr            error
	deleteMessageErr  error
	deleteReactionErr error
	memberStatus      string
	memberStatuses    map[int64]string
	memberStatusErr   error
	memberChecks      int
	onMemberCheck     func()
	bans              int
	messageDeletes    int
	reactionDeletes   int
	mutes             int
	unbans            int
	messages          []string
	messageChats      []int64
	sendMessageErr    error
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
func (t *telegramStub) GetChatMemberStatus(_ context.Context, _ int64, userID int64) (string, error) {
	t.memberChecks++
	if t.onMemberCheck != nil {
		t.onMemberCheck()
	}
	if status, ok := t.memberStatuses[userID]; ok {
		return status, t.memberStatusErr
	}
	if t.memberStatus == "" {
		return "member", t.memberStatusErr
	}
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
func (t *telegramStub) SendMessage(_ context.Context, chatID int64, message string) error {
	t.messageChats = append(t.messageChats, chatID)
	t.messages = append(t.messages, message)
	return t.sendMessageErr
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

func TestWorkerNotifiesResponsibleAdminAfterSuccessfulMessageDeletion(t *testing.T) {
	action := claimedAction(moderation.ActionDeleteMessage, 1)
	action.Notification = moderation.DeletionNotification{
		ChatID:         9001,
		AuthorUsername: "spam_account",
		AuthorUserID:   42,
		Message:        "Подключай VPN со скидкой",
		Reasons:        []string{"COMMERCIAL_PROMOTION", "VPN_PROMOTION"},
		RiskScore:      0.95,
	}
	repo := &repositoryStub{found: true, action: action}
	telegram := &telegramStub{memberStatuses: map[int64]string{9001: "administrator"}}
	worker := newTestWorker(t, repo, telegram)

	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked || !repo.succeeded {
		t.Fatalf("worked/error/succeeded = %v/%v/%v", worked, err, repo.succeeded)
	}
	if len(telegram.messages) != 1 || len(telegram.messageChats) != 1 || telegram.messageChats[0] != 9001 {
		t.Fatalf("notifications = %#v to %#v", telegram.messages, telegram.messageChats)
	}
	for _, wanted := range []string{"@spam_account", "Подключай VPN со скидкой", "коммерческая реклама", "реклама VPN"} {
		if !strings.Contains(telegram.messages[0], wanted) {
			t.Fatalf("notification %q does not contain %q", telegram.messages[0], wanted)
		}
	}
}

func TestWorkerRechecksAdministratorBeforeDeletingMessage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     string
		statusErr  error
		reason     string
		wantDelete bool
		wantCancel bool
		wantRetry  bool
	}{
		{"administrator", "administrator", nil, "", false, true, false},
		{"owner", "creator", nil, "", false, true, false},
		{"ordinary member", "member", nil, "", true, false, false},
		{"unavailable member status", "", errors.New("Telegram unavailable"), "", false, false, true},
		{"legacy profile-only action", "member", nil, moderation.ReasonProfileChannelAdvertising, false, true, false},
		{"confirmed channel member", "member", nil, moderation.ReasonConfirmedAdvertisingChannel, true, false, false},
		{"confirmed channel administrator", "administrator", nil, moderation.ReasonConfirmedAdvertisingChannel, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := claimedAction(moderation.ActionDeleteMessage, 1)
			action.AuthorizationReason = tc.reason
			repo := &repositoryStub{found: true, action: action}
			tg := &telegramStub{memberStatus: tc.status, memberStatusErr: tc.statusErr}
			worker := newTestWorker(t, repo, tg)
			if worked, err := worker.RunOnce(context.Background()); !worked || err != nil {
				t.Fatalf("RunOnce() = %v, %v", worked, err)
			}
			if got := tg.messageDeletes > 0; got != tc.wantDelete {
				t.Fatalf("delete = %v, want %v", got, tc.wantDelete)
			}
			if got := repo.cancelledErr != ""; got != tc.wantCancel {
				t.Fatalf("cancel = %v, want %v", got, tc.wantCancel)
			}
			if got := repo.retryError != ""; got != tc.wantRetry {
				t.Fatalf("retry = %v, want %v", got, tc.wantRetry)
			}
			if tc.wantCancel && repo.succeeded {
				t.Fatal("cancelled action cannot be marked succeeded")
			}
		})
	}
}

func TestWorkerCancelsDeletionWithoutRealAuthor(t *testing.T) {
	for _, userID := range []int64{0, 777000, 1087968824} {
		action := claimedAction(moderation.ActionDeleteMessage, 1)
		action.Target.UserID = userID
		repo := &repositoryStub{found: true, action: action}
		tg := &telegramStub{}
		worker := newTestWorker(t, repo, tg)
		if worked, err := worker.RunOnce(context.Background()); !worked || err != nil {
			t.Fatalf("RunOnce() = %v, %v", worked, err)
		}
		if tg.messageDeletes != 0 || repo.cancelledErr == "" {
			t.Fatalf("author %d: deletes=%d cancelled=%q", userID, tg.messageDeletes, repo.cancelledErr)
		}
	}
}

func TestWorkerRechecksAdministratorBeforeFirstBanAttempt(t *testing.T) {
	for _, tc := range []struct {
		name, status                   string
		statusErr                      error
		wantBan, wantCancel, wantRetry bool
	}{
		{"ordinary member", "member", nil, true, false, false},
		{"promoted administrator", "administrator", nil, false, true, false},
		{"owner", "creator", nil, false, true, false},
		{"status unavailable", "", errors.New("Telegram unavailable"), false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := claimedAction(moderation.ActionBanUser, 1)
			action.AuthorizationReason = moderation.ReasonConfirmedAdultAdvertisingChannel
			repo := &repositoryStub{found: true, action: action}
			tg := &telegramStub{memberStatus: tc.status, memberStatusErr: tc.statusErr}
			worked, err := newTestWorker(t, repo, tg).RunOnce(context.Background())
			if !worked || err != nil {
				t.Fatalf("RunOnce() = %v, %v", worked, err)
			}
			if tg.memberChecks != 1 || (tg.bans > 0) != tc.wantBan || (repo.cancelledErr != "") != tc.wantCancel || (repo.retryError != "") != tc.wantRetry {
				t.Fatalf("checks=%d bans=%d cancelled=%q retry=%q", tg.memberChecks, tg.bans, repo.cancelledErr, repo.retryError)
			}
			if !tc.wantBan && (repo.succeeded || len(tg.messages) != 0) {
				t.Fatal("unexecuted ban cannot be reported as successful")
			}
		})
	}
}

func TestWorkerCancelsBanWithoutRealMember(t *testing.T) {
	for _, userID := range []int64{0, 777000, 1087968824} {
		action := claimedAction(moderation.ActionBanUser, 1)
		action.Target.UserID = userID
		repo := &repositoryStub{found: true, action: action}
		tg := &telegramStub{}
		if worked, err := newTestWorker(t, repo, tg).RunOnce(context.Background()); !worked || err != nil {
			t.Fatalf("RunOnce() = %v, %v", worked, err)
		}
		if tg.bans != 0 || tg.memberChecks != 0 || repo.cancelledErr == "" {
			t.Fatalf("user %d: bans=%d checks=%d cancelled=%q", userID, tg.bans, tg.memberChecks, repo.cancelledErr)
		}
	}
}

func TestWorkerDoesNotNotifyAdminWhenMessageDeletionFails(t *testing.T) {
	action := claimedAction(moderation.ActionDeleteMessage, 1)
	action.Notification = moderation.DeletionNotification{ChatID: 9001, Message: "Спам"}
	repo := &repositoryStub{found: true, action: action}
	telegram := &telegramStub{deleteMessageErr: &telegramapi.APIError{ErrorCode: 403, Description: "Forbidden"}}
	worker := newTestWorker(t, repo, telegram)

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(telegram.messages) != 0 {
		t.Fatalf("notifications = %q", telegram.messages)
	}
}

func TestWorkerTreatsAlreadyDeletedMessageAsAssumedSuccess(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionDeleteMessage, 1)}
	telegram := &telegramStub{deleteMessageErr: &telegramapi.APIError{ErrorCode: 400, Description: "Bad Request: message to delete not found"}}
	worker := newTestWorker(t, repo, telegram)
	if worked, err := worker.RunOnce(context.Background()); err != nil || !worked || !repo.succeeded || !repo.assumed {
		t.Fatalf("delete recovery = %t/%v, successful/assumed = %t/%t", worked, err, repo.succeeded, repo.assumed)
	}
}

func TestWorkerExecutesScopedAdvertisingBanWithoutPostingInGroup(t *testing.T) {
	action := claimedAction(moderation.ActionBanUser, 1)
	action.AuthorizationReason = moderation.ReasonConfirmedAdvertisingAutoban
	repo := &repositoryStub{found: true, action: action}
	telegram := &telegramStub{}
	worker := newTestWorker(t, repo, telegram)
	if worked, err := worker.RunOnce(context.Background()); err != nil || !worked || telegram.bans != 1 || !repo.succeeded || len(telegram.messages) != 0 {
		t.Fatalf("ban = %t/%v, bans=%d, successful=%t, messages=%d", worked, err, telegram.bans, repo.succeeded, len(telegram.messages))
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

func TestWorkerNotifiesChatAfterSuccessfulBan(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 1)}
	telegram := &telegramStub{}
	worker := newTestWorker(t, repo, telegram)

	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked || !repo.succeeded {
		t.Fatalf("worked/error/succeeded = %v/%v/%v", worked, err, repo.succeeded)
	}
	if len(telegram.messages) != 1 || !strings.Contains(telegram.messages[0], "42") {
		t.Fatalf("notifications = %q", telegram.messages)
	}
}

func TestWorkerDoesNotAnnounceFailedBan(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 1)}
	telegram := &telegramStub{banErr: &telegramapi.APIError{ErrorCode: 403, Description: "Forbidden"}}
	worker := newTestWorker(t, repo, telegram)

	_, err := worker.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(telegram.messages) != 0 {
		t.Fatalf("notifications = %q", telegram.messages)
	}
}

func TestWorkerKeepsSuccessfulBanWhenNotificationFails(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 1)}
	telegram := &telegramStub{sendMessageErr: errors.New("notification unavailable")}
	worker := newTestWorker(t, repo, telegram)

	worked, err := worker.RunOnce(context.Background())
	if err != nil || !worked || !repo.succeeded || repo.retryError != "" || repo.permanentErr != "" {
		t.Fatalf(
			"worked/error/succeeded/retry/permanent = %v/%v/%v/%q/%q",
			worked, err, repo.succeeded, repo.retryError, repo.permanentErr,
		)
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
