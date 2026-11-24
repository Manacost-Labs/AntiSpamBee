package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestModerationReadinessRequiresQueue(t *testing.T) {
	server := moderationHealthServer(":8082", nil, func() bool { return false }, &workerMetrics{})
	for path, want := range map[string]int{"/healthz": http.StatusOK, "/readyz": http.StatusServiceUnavailable} {
		response := httptest.NewRecorder()
		server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != want {
			t.Errorf("%s = %d, want %d", path, response.Code, want)
		}
	}
}
