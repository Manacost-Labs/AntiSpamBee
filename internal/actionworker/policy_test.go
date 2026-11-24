package actionworker

import (
	"context"
	"errors"
	"testing"

	"antispambee/internal/moderation"
)

func TestWorkerRechecksCurrentPolicyOnEveryAttempt(t *testing.T) {
	for _, attempt := range []int{1, 3} {
		for _, actionType := range []moderation.ActionType{moderation.ActionDeleteMessage, moderation.ActionDeleteReaction, moderation.ActionBanUser} {
			for _, change := range []string{"allowlisted", "disabled", "observe", "unknown level"} {
				t.Run(string(actionType)+"/"+change+"/"+string(rune('0'+attempt)), func(t *testing.T) {
					policy := moderation.CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true}
					switch change {
					case "allowlisted":
						policy.IsAllowlisted = true
					case "disabled":
						policy.AutomaticActionsEnabled = false
					case "observe":
						policy.ProtectionLevel = "OBSERVE"
					case "unknown level":
						policy.ProtectionLevel = "UNKNOWN"
					}
					repo := &repositoryStub{found: true, action: claimedAction(actionType, attempt), policy: &policy}
					telegram := &telegramStub{}
					if worked, err := newTestWorker(t, repo, telegram).RunOnce(context.Background()); !worked || err != nil {
						t.Fatalf("RunOnce() = %v, %v", worked, err)
					}
					if repo.cancelledErr == "" || repo.succeeded || repo.policyCalls != 1 || telegram.bans+telegram.messageDeletes+telegram.reactionDeletes != 0 {
						t.Fatalf("stale action was not cancelled before mutation: repo=%+v telegram=%+v", repo, telegram)
					}
				})
			}
		}
	}
}

func TestWorkerChecksAutobanAndStrictProfileEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		action  moderation.ActionType
		reason  string
		level   string
		autoban bool
		cancel  bool
	}{
		{"ban disabled", moderation.ActionBanUser, moderation.ReasonConfirmedAdultChannel, "STRICT", false, true},
		{"ban standard", moderation.ActionBanUser, moderation.ReasonConfirmedFraudChannel, "STANDARD", true, true},
		{"profile delete standard", moderation.ActionDeleteMessage, moderation.ReasonConfirmedAdvertisingChannel, "STANDARD", true, true},
		{"semantic profile delete standard", moderation.ActionDeleteMessage, moderation.ReasonConfirmedProfileAdvertising, "STANDARD", true, true},
		{"advertising autoban standard", moderation.ActionBanUser, moderation.ReasonConfirmedAdvertisingAutoban, "STANDARD", true, true},
		{"adult fallback standard", moderation.ActionDeleteMessage, moderation.ReasonAutobanDisabled, "STANDARD", false, true},
		{"message delete standard", moderation.ActionDeleteMessage, moderation.ReasonLikelyAdvertising, "STANDARD", false, false},
		{"profile delete strict", moderation.ActionDeleteMessage, moderation.ReasonAutobanDisabled, "STRICT", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := moderation.CommunityPolicy{ProtectionLevel: tc.level, AutomaticActionsEnabled: true, AutobanEnabled: tc.autoban}
			repo := &repositoryStub{found: true, action: claimedAction(tc.action, 2), policy: &policy}
			repo.action.AuthorizationReason = tc.reason
			telegram := &telegramStub{}
			if _, err := newTestWorker(t, repo, telegram).RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if (repo.cancelledErr != "") != tc.cancel || repo.succeeded == tc.cancel {
				t.Fatalf("cancel=%v: repo=%+v", tc.cancel, repo)
			}
		})
	}
}

func TestWorkerPolicyReadFailureRetriesWithoutTelegramAction(t *testing.T) {
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 1), policyErr: errors.New("database unavailable")}
	telegram := &telegramStub{}
	if _, err := newTestWorker(t, repo, telegram).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.retryAt.IsZero() || repo.cancelledErr != "" || repo.succeeded || telegram.bans != 0 {
		t.Fatalf("policy failure did not defer action: repo=%+v telegram=%+v", repo, telegram)
	}
}

func TestWorkerReadsPolicyAfterMemberLookup(t *testing.T) {
	policy := moderation.CommunityPolicy{ProtectionLevel: "STRICT", AutomaticActionsEnabled: true, AutobanEnabled: true}
	repo := &repositoryStub{found: true, action: claimedAction(moderation.ActionBanUser, 1), policy: &policy}
	telegram := &telegramStub{onMemberCheck: func() { policy.IsAllowlisted = true }}
	if _, err := newTestWorker(t, repo, telegram).RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if repo.cancelledErr == "" || repo.succeeded || telegram.bans != 0 {
		t.Fatalf("policy change during Telegram lookup was ignored: repo=%+v telegram=%+v", repo, telegram)
	}
}

func TestWorkerManualCommandsKeepTheirAuthorization(t *testing.T) {
	for _, actionType := range []moderation.ActionType{moderation.ActionDeleteMessage, moderation.ActionBanUser, moderation.ActionMuteUser, moderation.ActionUnbanUser} {
		t.Run(string(actionType), func(t *testing.T) {
			repo := &repositoryStub{found: true, action: claimedAction(actionType, 1), policyErr: errors.New("must not query automatic policy")}
			repo.action.AuthorizationReason = moderation.ReasonModeratorCommand
			if _, err := newTestWorker(t, repo, &telegramStub{}).RunOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !repo.succeeded || repo.policyCalls != 0 {
				t.Fatalf("manual command blocked by automatic policy: %+v", repo)
			}
		})
	}
}
