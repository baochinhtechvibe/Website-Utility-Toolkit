package dns

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoHResolverRejectsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream error", http.StatusBadGateway)
	}))
	defer server.Close()

	resolver := &DoHResolver{Endpoint: server.URL, SupportsJSON: true}
	if _, err := resolver.Query("example.com.", 1); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("DoHResolver.Query() error = %v, want HTTP 502", err)
	}
}

func TestDoHResolverRejectsOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxDoHResponseBody+1)))
	}))
	defer server.Close()

	resolver := &DoHResolver{Endpoint: server.URL, SupportsJSON: true}
	if _, err := resolver.Query("example.com.", 1); err == nil || !strings.Contains(err.Error(), "vượt quá giới hạn") {
		t.Fatalf("DoHResolver.Query() error = %v, want body limit error", err)
	}
}
