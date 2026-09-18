package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"antispambee/internal/eventstream"
	"antispambee/internal/telegram"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid gateway configuration", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config); err != nil {
		slog.Error("gateway stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, config config) error {
	connection, err := nats.Connect(
		config.NATSURL,
		nats.Name("antispambee-gateway"),
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
	cancelProvision()
	if err != nil {
		return err
	}

	publisher, err := eventstream.NewPublisher(js, config.Stream, config.Subject)
	if err != nil {
		return err
	}
	webhook, err := telegram.NewWebhookHandler(telegram.WebhookConfig{
		TenantID: config.TenantID,
		BotID:    config.BotID,
		Secret:   config.WebhookSecret,
	}, publisher)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("POST /telegram/webhook", webhook)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	server := &http.Server{
		Addr:              config.HTTPAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	slog.Info("gateway listening", "address", config.HTTPAddress)
	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve gateway HTTP: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown gateway HTTP: %w", err)
		}
		return nil
	}
}
