package openrouter

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const appServerRetryDelay = 30 * time.Second

// NewAppServerContentClient connects to a local Codex Chat Completions bridge.
// The same evidence validation runs for responses from either backend.
func NewAppServerContentClient(socketPath, tokenFile, model string, fallback *Client) (*Client, error) {
	if !filepath.IsAbs(socketPath) || !filepath.IsAbs(tokenFile) || strings.TrimSpace(model) == "" {
		return nil, fmt.Errorf("Codex App Server requires absolute socket and token paths and a model")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read Codex App Server bridge token: %w", err)
	}
	apiKey := strings.TrimSpace(string(token))
	if apiKey == "" {
		return nil, fmt.Errorf("Codex App Server bridge token is empty")
	}
	var local net.Dialer
	return &Client{
		apiKey:          apiKey,
		baseURL:         "http://localhost",
		model:           model,
		appServer:       true,
		contentFallback: fallback,
		now:             time.Now,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return local.DialContext(ctx, "unix", socketPath)
				},
				IdleConnTimeout: 30 * time.Second,
			},
		},
	}, nil
}
