package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
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
			return consume(ctx, consumer, pool, profiles, semantic, config.RetryDelay)
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
	handler, err := eventstream.NewHandler(processor, retryDelay)
	if err != nil {
		return err
	}

	consumeContext, err := consumer.Consume(
		func(message jetstream.Msg) {
			if err := handler.Handle(ctx, message); err != nil {
				slog.Error("moderation event processing failed", "error", err)
			}
		},
		jetstream.ConsumeErrHandler(func(_ jetstream.ConsumeContext, err error) {
			slog.Error("JetStream consumer error", "error", err)
		}),
	)
	if err != nil {
		return fmt.Errorf("start moderation consumer: %w", err)
	}

	slog.Info("moderation worker started")
	<-ctx.Done()
	consumeContext.Drain()

	select {
	case <-consumeContext.Closed():
		return nil
	case <-time.After(10 * time.Second):
		consumeContext.Stop()
		return fmt.Errorf("drain moderation consumer: timeout")
	}
}
