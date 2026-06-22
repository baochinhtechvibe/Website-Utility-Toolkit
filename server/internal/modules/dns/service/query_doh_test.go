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

func TestParseDohRecord_SRV(t *testing.T) {
	ans := dohRecord{
		Type: 33, // SRV
		Data: "10 5 5060 sip.example.com.",
		TTL:  300,
	}

	rec := parseDohRecord(ans, "_sip._tcp.example.com")
	if rec == nil {
		t.Fatal("Expected record, got nil")
	}

	if rec.Type != "SRV" {
		t.Errorf("Expected Type SRV, got %s", rec.Type)
	}
	if rec.Target != "sip.example.com" {
		t.Errorf("Expected Target sip.example.com, got %s", rec.Target)
	}
	if rec.Priority != 10 {
		t.Errorf("Expected Priority 10, got %d", rec.Priority)
	}
	if rec.Weight != 5 {
		t.Errorf("Expected Weight 5, got %d", rec.Weight)
	}
	if rec.Port != 5060 {
		t.Errorf("Expected Port 5060, got %d", rec.Port)
	}
	if rec.TTL != 300 {
		t.Errorf("Expected TTL 300, got %d", rec.TTL)
	}
}
