package postgresstore

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/events"
	"antispambee/internal/moderation"
	"github.com/jackc/pgx/v5/pgxpool"
)

func commandTestStore(t *testing.T) (*Store, *pgxpool.Pool) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	store, err := New(pool)
	if err != nil {
		t.Fatal(err)
	}
	return store, pool
}

func commandTestEvent(t *testing.T, id int64) events.TelegramUpdate {
	t.Helper()
	identity, err := events.NewTelegramIdentity(123456, id)
	if err != nil {
		t.Fatal(err)
	}
	return events.TelegramUpdate{SchemaVersion: "1", TenantID: "9d83e552-8910-4c46-b55a-63074078829e", EventID: identity.EventID, SourceKey: identity.SourceKey, BotID: 123456, UpdateID: id}
}

func commandTestOutcome(mutation moderation.CommandMutation) moderation.Outcome {
	score, confidence := 0.0, 1.0
	return moderation.Outcome{
		State:    moderation.ProcessedAllow,
		Decision: moderation.Decision{DecisionConfidence: 1, EvidenceCoverage: 1, RecommendedAction: moderation.ActionAllow, AuthorizedAction: moderation.ActionAllow, AuthorizationReason: moderation.ReasonModeratorCommand},
		Signals:  []detection.Signal{{SchemaVersion: "1", Detector: "system.command", DetectorVersion: "command-v1", Category: "system.command", Status: detection.StatusAvailable, Score: &score, Confidence: &confidence, Severity: detection.SeverityInfo, EvidenceCoverage: 1, ReasonCodes: []string{moderation.ReasonModeratorCommand}, MatchedRules: []string{}, CreatedAt: time.Now().UTC()}},
		Command:  &moderation.CommandCommit{Mutation: mutation, Replies: []moderation.CommandReply{{ChatID: 1, Text: "original reply"}}},
	}
}

func TestCommandCommitReplayPreservesNewerSettingsAndOriginalReply(t *testing.T) {
	for index, tc := range []struct {
		name          string
		first, second moderation.CommandMutation
		check         func(moderation.CommunityPolicy) bool
	}{
		{"protection", moderation.CommandMutation{ChatID: -19001, ProtectionLevel: "STRICT", ModeratorUserID: 1}, moderation.CommandMutation{ChatID: -19001, ProtectionLevel: "OBSERVE", ModeratorUserID: 2}, func(p moderation.CommunityPolicy) bool {
			return p.ProtectionLevel == "OBSERVE" && !p.AutomaticActionsEnabled && p.ModeratorChatID == 2
		}},
		{"allowlist", moderation.CommandMutation{ChatID: -19002, Allowlist: &moderation.AllowlistChange{UserID: 42, AddedBy: 1, Allowed: true}}, moderation.CommandMutation{ChatID: -19002, Allowlist: &moderation.AllowlistChange{UserID: 42, AddedBy: 2, Allowed: false}}, func(p moderation.CommunityPolicy) bool { return !p.IsAllowlisted }},
		{"binding", moderation.CommandMutation{ChatID: -19003, ModeratorUserID: 1, SenderChatID: -19100}, moderation.CommandMutation{ChatID: -19003, ModeratorUserID: 2, SenderChatID: -19200}, func(p moderation.CommunityPolicy) bool { return p.ModeratorChatID == 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, pool := commandTestStore(t)
			ctx := context.Background()
			first, second := commandTestEvent(t, 910001+int64(index)*2), commandTestEvent(t, 910002+int64(index)*2)
			if _, err := pool.Exec(ctx, "DELETE FROM moderation_events WHERE event_id IN ($1,$2)", first.EventID, second.EventID); err != nil {
				t.Fatal(err)
			}
			old, newer := commandTestOutcome(tc.first), commandTestOutcome(tc.second)
			if err := store.RecordTerminal(ctx, first, old); err != nil {
				t.Fatal(err)
			}
			if err := store.RecordTerminal(ctx, second, newer); err != nil {
				t.Fatal(err)
			}
			old.Command.Replies[0].Text = "recomputed reply must not replace original"
			if err := store.RecordTerminal(ctx, first, old); err != nil {
				t.Fatal(err)
			}
			policy, err := store.GetCommunityPolicy(ctx, first.TenantID, tc.first.ChatID, 42)
			if err != nil || !tc.check(policy) {
				t.Fatalf("current policy=%+v err=%v", policy, err)
			}
			if tc.name == "binding" {
				oldBinding, err := store.IsAuthorizedSenderChat(ctx, first.TenantID, tc.first.ChatID, -19100)
				if err != nil || oldBinding {
					t.Fatalf("old binding=%v err=%v", oldBinding, err)
				}
				newBinding, err := store.IsAuthorizedSenderChat(ctx, first.TenantID, tc.first.ChatID, -19200)
				if err != nil || !newBinding {
					t.Fatalf("new binding=%v err=%v", newBinding, err)
				}
			}
			var count int
			var payload []byte
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM moderation_command_reply_outbox WHERE event_id=$1", first.EventID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT payload FROM moderation_command_reply_outbox WHERE event_id=$1", first.EventID).Scan(&payload); err != nil {
				t.Fatal(err)
			}
			var reply moderation.CommandReply
			if err := json.Unmarshal(payload, &reply); err != nil {
				t.Fatal(err)
			}
			if count != 1 || reply.Text != "original reply" {
				t.Fatalf("reply count=%d reply=%+v", count, reply)
			}
			if processed, err := store.ModerationEventProcessed(ctx, first); err != nil || !processed {
				t.Fatalf("committed command processed=%v err=%v", processed, err)
			}
		})
	}
}

func TestCommandCommitRollsBackSettingsAndOutboxTogether(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	event := commandTestEvent(t, 910020)
	if _, err := pool.Exec(ctx, "DELETE FROM moderation_events WHERE event_id=$1", event.EventID); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCommunityProtection(ctx, event.TenantID, -19020, "OBSERVE"); err != nil {
		t.Fatal(err)
	}
	outcome := commandTestOutcome(moderation.CommandMutation{ChatID: -19020, ProtectionLevel: "STRICT", ModeratorUserID: 1})
	outcome.Command.Replies[0].ChatID = 0 // Failure occurs after the settings mutation.
	if err := store.RecordTerminal(ctx, event, outcome); err == nil {
		t.Fatal("expected invalid reply to abort transaction")
	}
	policy, err := store.GetCommunityPolicy(ctx, event.TenantID, -19020, 42)
	if err != nil || policy.ProtectionLevel != "OBSERVE" || policy.ModeratorChatID != 0 {
		t.Fatalf("rolled back policy=%+v err=%v", policy, err)
	}
	var eventsCount, replyCount, commitCount int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM moderation_events WHERE event_id=$1),
		(SELECT count(*) FROM moderation_command_reply_outbox WHERE event_id=$1),
		(SELECT count(*) FROM moderation_command_commits WHERE event_id=$1)`, event.EventID).Scan(&eventsCount, &replyCount, &commitCount); err != nil {
		t.Fatal(err)
	}
	if eventsCount+replyCount+commitCount != 0 {
		t.Fatal("failed transaction left committed records")
	}
}

func TestLegacyCommandUpgradeDoesNotReapplySettings(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	event := commandTestEvent(t, 910030)
	if _, err := pool.Exec(ctx, "DELETE FROM moderation_events WHERE event_id=$1", event.EventID); err != nil {
		t.Fatal(err)
	}
	outcome := commandTestOutcome(moderation.CommandMutation{ChatID: -19030, ProtectionLevel: "STRICT"})
	legacy := outcome
	legacy.Command = nil
	if err := store.RecordTerminal(ctx, event, legacy); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCommunityProtection(ctx, event.TenantID, -19030, "OBSERVE"); err != nil {
		t.Fatal(err)
	}
	if processed, err := store.ModerationEventProcessed(ctx, event); err != nil || processed {
		t.Fatalf("legacy processed=%v err=%v", processed, err)
	}
	if err := store.RecordTerminal(ctx, event, outcome); err != nil {
		t.Fatal(err)
	}
	policy, err := store.GetCommunityPolicy(ctx, event.TenantID, -19030, 42)
	if err != nil || policy.ProtectionLevel != "OBSERVE" {
		t.Fatalf("legacy upgrade changed policy=%+v err=%v", policy, err)
	}
	if processed, err := store.ModerationEventProcessed(ctx, event); err != nil || !processed {
		t.Fatalf("upgraded processed=%v err=%v", processed, err)
	}
}

func TestCommandReplyLeaseRecoveryFencesOldAttempt(t *testing.T) {
	store, pool := commandTestStore(t)
	ctx := context.Background()
	event := commandTestEvent(t, 910040)
	if _, err := pool.Exec(ctx, "TRUNCATE moderation_command_reply_outbox"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM moderation_events WHERE event_id=$1", event.EventID); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTerminal(ctx, event, commandTestOutcome(moderation.CommandMutation{})); err != nil {
		t.Fatal(err)
	}
	first, found, err := store.ClaimCommandReply(ctx, "same-owner", time.Second)
	if err != nil || !found {
		t.Fatalf("first claim=%+v found=%v err=%v", first, found, err)
	}
	if _, err := pool.Exec(ctx, "UPDATE moderation_command_reply_outbox SET lease_until=now()-interval '1 second' WHERE reply_id=$1", first.ReplyID); err != nil {
		t.Fatal(err)
	}
	second, found, err := store.ClaimCommandReply(ctx, "same-owner", time.Second)
	if err != nil || !found || second.Attempts != 2 || second.ReplyID != first.ReplyID {
		t.Fatalf("reclaim=%+v found=%v err=%v", second, found, err)
	}
	if err := store.FinishCommandReply(ctx, first, "SENT", time.Now(), ""); err == nil {
		t.Fatal("stale reply lease completed")
	}
	if err := store.FinishCommandReply(ctx, second, "RETRYABLE", time.Now().Add(-time.Second), "temporary failure"); err != nil {
		t.Fatal(err)
	}
	third, found, err := store.ClaimCommandReply(ctx, "other-owner", time.Second)
	if err != nil || !found || third.Attempts != 3 || third.Reply.Text != "original reply" {
		t.Fatalf("retry=%+v found=%v err=%v", third, found, err)
	}
	if err := store.FinishCommandReply(ctx, third, "SENT", time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ClaimCommandReply(ctx, "other-owner", time.Second); err != nil || found {
		t.Fatalf("finished reply claimed again: found=%v err=%v", found, err)
	}
	var payload string
	if err := pool.QueryRow(ctx, "SELECT payload::text FROM moderation_command_reply_outbox WHERE reply_id=$1", third.ReplyID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if payload != "{}" {
		t.Fatalf("sent reply payload retained: %s", payload)
	}
}
