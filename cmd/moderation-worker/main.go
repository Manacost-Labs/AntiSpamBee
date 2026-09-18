package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"antispambee/internal/detection"
	"antispambee/internal/eventstream"
	"antispambee/internal/moderation"
	"antispambee/internal/openrouter"
	"antispambee/internal/postgresstore"
	"antispambee/internal/telegramapi"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid moderation worker configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config); err != nil {
		slog.Error("moderation worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, config config) error {
	profiles, err := telegramapi.NewClient(telegramapi.ClientConfig{Token: config.TelegramBotToken})
	if err != nil {
		return err
	}
	var semantic *openrouter.Client
	if config.OpenRouterAPIKey != "" {
		semantic, err = openrouter.NewClient(openrouter.ClientConfig{
			APIKey:  config.OpenRouterAPIKey,
			BaseURL: config.OpenRouterBaseURL,
			Model:   config.OpenRouterModel,
		})
		if err != nil {
			return err
		}
	}

	pool, err := pgxpool.New(ctx, config.DatabaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL pool: %w", err)
	}
	defer pool.Close()

	connectCtx, cancelConnect := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(connectCtx)
	cancelConnect()
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}

	connection, err := nats.Connect(
		config.NATSURL,
		nats.Name("antispambee-moderation-worker"),
		nats.Timeout(5*time.Second),
	)
	if err != nil {
		return fmt.Errorf("connect to NATS: %w", err)
	}
	defer connection.Close()

	js, err := jetstream.New(connection)
	if err != nil {
		return fmt.Errorf("create JetStream client: %w", err)
	}

	provisionCtx, cancelProvision := context.WithTimeout(ctx, 10*time.Second)
	err = eventstream.EnsureTelegramStream(provisionCtx, js, config.Stream, config.Subject)
	if err == nil {
		var consumer jetstream.Consumer
		consumer, err = eventstream.EnsureModerationConsumer(
			provisionCtx,
			js,
			config.Stream,
			config.Subject,
			config.Consumer,
		)
		if err == nil {
			cancelProvision()
			return consume(ctx, consumer, pool, profiles, semantic, config.RetryDelay, config.ModeratorChatID, config.HTTPAddress)
		}
	}
	cancelProvision()
	return err
}

func consume(
	ctx context.Context,
	consumer jetstream.Consumer,
	pool *pgxpool.Pool,
	profiles *telegramapi.Client,
	semantic *openrouter.Client,
	retryDelay time.Duration,
	moderatorChatID int64,
	httpAddress string,
) error {
	store, err := postgresstore.New(pool)
	if err != nil {
		return err
	}
	options := []moderation.ProcessorOption{
		moderation.WithBehaviorStore(store),
		moderation.WithPolicyStore(store),
	}
	if semantic != nil {
		options = append(options, moderation.WithSemanticAnalyzer(semantic))
	}
	processor, err := moderation.NewProcessor(store, profiles, detection.NewProfileDetector(), options...)
	if err != nil {
		return err
	}
	router, err := moderation.NewCommandRouter(store, profiles, processor, moderatorChatID)
	if err != nil {
		return err
	}
	handler, err := eventstream.NewHandler(router, retryDelay)
	if err != nil {
		return err
	}

	metrics := &workerMetrics{}
	consumeContext, err := consumer.Consume(
		func(message jetstream.Msg) {
			if err := handler.Handle(ctx, message); err != nil {
				metrics.failed.Add(1)
				slog.Error("moderation event processing failed", "error", err)
				return
			}
			metrics.processed.Add(1)
		},
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			slog.Error("JetStream consumer error", "error", err)
		}),
	)
	if err != nil {
		return fmt.Errorf("start moderation consumer: %w", err)
	}

	server := moderationHealthServer(httpAddress, pool, metrics)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	slog.Info("moderation worker started")
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			consumeContext.Stop()
			return fmt.Errorf("serve moderation worker health endpoint: %w", err)
		}
	}
	consumeContext.Drain()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown moderation worker health endpoint: %w", err)
	}

	select {
	case <-consumeContext.Closed():
		return nil
	case <-time.After(10 * time.Second):
		consumeContext.Stop()
		return fmt.Errorf("drain moderation consumer: timeout")
	}
}

type workerMetrics struct {
	processed atomic.Uint64
	failed    atomic.Uint64
}

func moderationHealthServer(address string, pool *pgxpool.Pool, metrics *workerMetrics) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, request *http.Request) {
		ctx, cancel := context.WithTimeout(request.Context(), time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = fmt.Fprintf(w,
			"antispambee_events_processed_total %d\nantispambee_events_failed_total %d\n",
			metrics.processed.Load(), metrics.failed.Load(),
		)
	})
	return &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
}
