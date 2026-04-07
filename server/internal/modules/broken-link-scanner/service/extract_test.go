package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

func TestExtractLinks_BaseRedirection(t *testing.T) {
	// Target Server Simulation
	// 1. Root redirects to Home
	// 2. Home returns an HTML with relative path
	handler := http.NewServeMux()
	handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/home", http.StatusMovedPermanently)
	})
	handler.HandleFunc("/home", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><img src="/app.js"></body></html>`))
	})
	
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req := models.ScanRequest{
		URL:   ts.URL,
		Scope: "all",
	}

	data, validLinks, err := ExtractLinks(req)
	assert.NoError(t, err)

	// Since it redirected to /home, the final base context ought to be http://ts.URL/home
	assert.Equal(t, ts.URL+"/home", data.FinalPageURL)
	assert.Len(t, validLinks, 1)

	// The relative src="/app.js" must resolve against ts.URL, not relative to `/home` context-wise because it's absolute to host
	assert.Equal(t, ts.URL+"/app.js", validLinks[0].FinalURL)
}

func TestDedupeAndNormalize_SSRF_Skip(t *testing.T) {
	base, _ := url.Parse("https://example.com/blog")

	raw := []unverifiedLink{
		{Kind: "<a>", RawURL: "mailto:hello@example.com"},
		{Kind: "<a>", RawURL: "javascript:alert(1)"},
		{Kind: "<a>", RawURL: "data:image/png;base64,123"},
		{Kind: "<a>", RawURL: "http://127.0.0.1/admin"},          // Note: SSRF filter is on dialer, but scope might keep it here. Wait, dedupeAndNormalize just parses valid schemas.
		{Kind: "<a>", RawURL: "https://example.com/blog#header"}, // Test fragment skipping
		{Kind: "<a>", RawURL: "https://example.com/blog"},        // Deduping the one above
	}

	result, invalidCount := dedupeAndNormalize(raw, base, "all")

	assert.Equal(t, 3, invalidCount) // mailto, javascript, data
	// The #header was stripped, making it equal to the last one, resulting in 2 items merging into 1. The 127.0.0.1 item is retained here, it is blocked later via Dialer.
	assert.Len(t, result, 2)
}

func TestScope_SameHost(t *testing.T) {
	base, _ := url.Parse("https://example.com")

	raw := []unverifiedLink{
		{RawURL: "https://example.com/about"},
		{RawURL: "https://cdn.example.com/styles.css"},
		{RawURL: "https://google.com"},
	}

	result, invalidCount := dedupeAndNormalize(raw, base, "same-host")
	
	// External links skipped due to scope shouldn't be counted as Invalid
	assert.Equal(t, 0, invalidCount) 
	assert.Len(t, result, 1)
	assert.Equal(t, "https://example.com/about", result[0].FinalURL)
}

func TestSSRFRejectOnDial(t *testing.T) {
	// A safe HTTP client handles actual connections.
	client := SafeHTTPClient(false, 2*time.Second)

	// Attempt connecting to localhost
	req, _ := http.NewRequestWithContext(context.TODO(), "GET", "http://127.0.0.1:8080/", nil)
	
	_, err := client.Do(req)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF Blocked")
}
