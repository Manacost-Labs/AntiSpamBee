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

	"antispambee/internal/actionworker"
	"antispambee/internal/postgresstore"
	"antispambee/internal/telegramapi"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	config, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid action worker configuration", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, config); err != nil {
		slog.Error("action worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, config config) error {
	pool, err := pgxpool.New(ctx, config.DatabaseURL)
	if err != nil {
		return fmt.Errorf("configure PostgreSQL pool: %w", err)
	}
	defer pool.Close()
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(connectCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	store, err := postgresstore.New(pool)
	if err != nil {
		return err
	}
	telegram, err := telegramapi.NewClient(telegramapi.ClientConfig{Token: config.TelegramBotToken})
	if err != nil {
		return err
	}
	worker, err := actionworker.New(store, telegram, config.WorkerID)
	if err != nil {
		return err
	}

	server := healthServer(config.HTTPAddress, pool)
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.ListenAndServe() }()
	workerErrors := make(chan error, 1)
	go func() { workerErrors <- consumeActions(ctx, worker, config.PollInterval) }()
	slog.Info("action worker started", "worker_id", config.WorkerID)

	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve action worker health endpoint: %w", err)
		}
	case err := <-workerErrors:
		if err != nil {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown action worker health endpoint: %w", err)
	}
	return nil
}

type actionRunner interface {
	RunOnce(context.Context) (bool, error)
}

func consumeActions(ctx context.Context, worker actionRunner, pollInterval time.Duration) error {
	for {
		worked, err := worker.RunOnce(ctx)
		if err != nil && ctx.Err() == nil {
			slog.Error("moderation action attempt failed", "error", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if worked && err == nil {
			continue
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func healthServer(address string, pool *pgxpool.Pool) *http.Server {
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
	return &http.Server{
		Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
	}
}
