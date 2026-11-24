package postgresstore

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"antispambee/internal/actionworker"
	"antispambee/internal/detection"
	"antispambee/internal/eventstream"
	"antispambee/internal/moderation"
	"antispambee/internal/telegramapi"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type burstClassifier struct{}

func (burstClassifier) AnalyzeContent(ctx context.Context, content detection.SemanticAdContent) []detection.Signal {
	// Simulate a remote model without sending test traffic to a provider.
	timer := time.NewTimer(25 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil
	case <-timer.C:
	}
	score, confidence := 0.0, 1.0
	signal := detection.Signal{SchemaVersion: "1", Detector: detection.SemanticMessageDetector, DetectorVersion: "burst-test", Category: "spam.advertising",
		Status: detection.StatusAvailable, Score: &score, Confidence: &confidence, Severity: detection.SeverityInfo, CreatedAt: time.Now()}
	if strings.Contains(content.Message.Text, "монтаж подкаста") {
		score = .96
		signal.EvidenceCoverage = 1
		signal.EvidenceExcerpt = content.Message.Text
	}
	return []detection.Signal{signal}
}

func TestModerationBurst100ThroughDurableQueue(t *testing.T) {
	serverURL := os.Getenv("TEST_NATS_URL")
	if serverURL == "" {
		t.Skip("TEST_NATS_URL is not set")
	}
	store, pool := commandTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const group = int64(-100887120)
	const messageCount = 100
	const firstUpdate = 901200
	if _, err := pool.Exec(ctx, `DELETE FROM moderation_events WHERE bot_id=123456 AND telegram_update_id>=901200 AND telegram_update_id<901300`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM moderation_campaign_observations WHERE chat_id=$1`, group); err != nil {
		t.Fatal(err)
	}
	tenant := commandTestEvent(t, firstUpdate).TenantID
	if err := setCommunityProtection(ctx, pool, tenant, group, "STRICT"); err != nil {
		t.Fatal(err)
	}
	var throttled atomic.Bool
	telegramServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result any = true
		switch {
		case strings.HasSuffix(r.URL.Path, "/getChat"):
			result = map[string]any{"type": "private"}
		case strings.HasSuffix(r.URL.Path, "/getChatMember"):
			result = map[string]any{"status": "member"}
		case strings.HasSuffix(r.URL.Path, "/deleteMessage") && throttled.CompareAndSwap(false, true):
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"test throttling","parameters":{"retry_after":1}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": result})
	}))
	defer telegramServer.Close()
	telegram, err := telegramapi.NewClient(telegramapi.ClientConfig{Token: "burst-test", BaseURL: telegramServer.URL, HTTPClient: telegramServer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	processor, err := moderation.NewProcessor(store, telegram, detection.NewProfileDetector(), moderation.WithPolicyStore(store),
		moderation.WithBehaviorStore(store), moderation.WithContentAnalyzer(burstClassifier{}, telegram, group),
		moderation.WithAdvertisingAutoban(group, burstClassifier{}), moderation.WithModerationOperations(group, []byte("burst-test-key"), store))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := actionworker.New(store, telegram, "burst-test")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("BURST_TEST_%d", time.Now().UnixNano())
	subject := "test." + name
	if err := eventstream.EnsureTelegramStream(ctx, js, name, subject); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(context.Background(), name) }()
	consumer, err := eventstream.EnsureModerationConsumer(ctx, js, name, subject, "test-worker")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := eventstream.NewHandler(processor, time.Second, eventstream.WithProcessedEventStore(store))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	for index := 0; index < messageCount; index++ {
		event := commandTestEvent(t, firstUpdate+int64(index))
		text := "Обсуждаем колоду и новый набор карт"
		if index%4 == 1 {
			text = "Нужны люди для доставки заказов, оплата 13 000 рублей за смену. Интересны детали? Пишите @burst_offer"
		}
		if index%4 == 2 {
			text = "Предлагаю монтаж подкаста за 25 евро, обращайтесь к @burst_offer"
		}
		event.Payload = []byte(fmt.Sprintf(`{"message":{"message_id":%d,"date":%d,"from":{"id":%d},"chat":{"id":%d,"type":"supergroup"},"text":%q}}`, index+1, start.Unix(), 7000+index, group, text))
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(ctx, subject, data); err != nil {
			t.Fatal(err)
		}
	}
	errorsFound := make(chan error, 1)
	consumption, err := consumer.Consume(func(message jetstream.Msg) {
		if err := handler.Handle(ctx, message); err != nil {
			select {
			case errorsFound <- err:
			default:
			}
		}
	}, jetstream.PullMaxMessages(eventstream.ModerationPullBatchSize))
	if err != nil {
		t.Fatal(err)
	}
	defer consumption.Stop()
	for {
		select {
		case err := <-errorsFound:
			t.Fatal(err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		default:
		}
		worked, err := worker.RunOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var processed, completed int
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM moderation_events WHERE bot_id=123456 AND telegram_update_id>=901200 AND telegram_update_id<901300),
			(SELECT count(*) FROM moderation_actions WHERE chat_id=$1 AND status IN ('SUCCEEDED','SUCCEEDED_ASSUMED'))`, group).Scan(&processed, &completed); err != nil {
			t.Fatal(err)
		}
		if processed == messageCount && completed == 100 {
			break
		}
		if !worked {
			time.Sleep(10 * time.Millisecond)
		}
	}
	rows, err := pool.Query(ctx, `SELECT action_type,count(*),max(attempt_count),
		1000*extract(epoch from percentile_disc(.5) WITHIN GROUP(ORDER BY updated_at-$2::timestamptz))::double precision,
		1000*extract(epoch from percentile_disc(.95) WITHIN GROUP(ORDER BY updated_at-$2::timestamptz))::double precision
		FROM moderation_actions WHERE chat_id=$1 GROUP BY 1 ORDER BY 1`, group, start)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var action string
		var count, attempts int
		var p50, p95 float64
		if err := rows.Scan(&action, &count, &attempts, &p50, &p95); err != nil {
			t.Fatal(err)
		}
		if count != 50 || (action == "DELETE_MESSAGE" && attempts != 2) {
			t.Fatalf("unexpected %s count/attempts: %d/%d", action, count, attempts)
		}
		t.Logf("%s count=%d attempts_max=%d queue_to_result_p50_ms=%.0f p95_ms=%.0f", action, count, attempts, p50, p95)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("100 updates processed in %s with Telegram and OpenRouter stubs", time.Since(start).Round(time.Millisecond))
}
