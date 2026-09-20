package postgresstore

import (
	"antispambee/internal/events"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
	"time"
)

func assertDurableEvidenceAndOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *Store, event events.TelegramUpdate) {
	t.Helper()
	history, err := store.ListModerationHistory(ctx, event.TenantID, -100777)
	if err != nil || len(history) != 1 || history[0].Evidence.Message.Text != "Подключай VPN со скидкой" {
		t.Fatalf("archive after deletion: %v %v", history, err)
	}
	if history, err := store.ListModerationHistory(ctx, "00000000-0000-4000-8000-000000000999", -100777); err != nil || len(history) != 0 {
		t.Fatalf("tenant isolation failed: %v %v", history, err)
	}
	n, found, err := store.ClaimNotification(ctx, "notify-1", time.Second)
	if err != nil || !found || n.Payload.Message != "Подключай VPN со скидкой" {
		t.Fatalf("outbox after completion: %+v %v %v", n, found, err)
	}
	if _, found, err := store.ClaimNotification(ctx, "notify-2", time.Second); err != nil || found {
		t.Fatalf("leased notification visible: %v %v", found, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE moderation_notification_outbox SET lease_until=now()-interval '1 second' WHERE action_id=$1`, n.ActionID); err != nil {
		t.Fatal(err)
	}
	reclaimed, found, err := store.ClaimNotification(ctx, "notify-2", time.Second)
	if err != nil || !found || reclaimed.Attempts != 2 {
		t.Fatalf("restart recovery: %+v %v %v", reclaimed, found, err)
	}
	if err := store.FinishNotification(ctx, n, "SENT", time.Now(), ""); err == nil {
		t.Fatal("stale lease completed")
	}
	if err := store.FinishNotification(ctx, reclaimed, "RETRYABLE", time.Now().Add(-time.Second), "temporary"); err != nil {
		t.Fatal(err)
	}
	reclaimed, found, err = store.ClaimNotification(ctx, "notify-3", time.Second)
	if err != nil || !found || reclaimed.Attempts != 3 {
		t.Fatalf("retry: %+v %v %v", reclaimed, found, err)
	}
	if err := store.FinishNotification(ctx, reclaimed, "SENT", time.Now(), ""); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ClaimNotification(ctx, "notify-4", time.Second); err != nil || found {
		t.Fatalf("completed notification replayed: %v %v", found, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE moderation_evidence SET expires_at=now()-interval '1 second' WHERE event_id=$1`, event.EventID); err != nil {
		t.Fatal(err)
	}
	if history, err := store.ListModerationHistory(ctx, event.TenantID, -100777); err != nil || len(history) != 0 {
		t.Fatalf("expired evidence disclosed: %v %v", history, err)
	}
	if err := store.PurgeExpiredEvidence(ctx); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM moderation_evidence WHERE event_id=$1`, event.EventID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("retention failed: %d %v", remaining, err)
	}
}
