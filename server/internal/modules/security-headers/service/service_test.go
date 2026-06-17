package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAnalyzeHeaders_Basic(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	resp.Header.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'")
	resp.Header.Set("X-Frame-Options", "SAMEORIGIN")
	resp.Header.Set("X-Content-Type-Options", "nosniff")
	resp.Header.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	resp.Header.Set("Permissions-Policy", "camera=()")
	resp.Header.Set("Cross-Origin-Opener-Policy", "same-origin")

	result := analyzeHeaders(resp, "https")

	if result.Penalty != 0 {
		t.Errorf("Expected 0 penalty for perfectly secure headers, got %d", result.Penalty)
	}
}

func TestAnalyzeHeaders_XFOSubstitution(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	// No X-Frame-Options, but CSP has frame-ancestors
	resp.Header.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	
	result := analyzeHeaders(resp, "https")

	// Penalty should not be applied for missing XFO
	for _, h := range result.Headers {
		if h.Name == "X-Frame-Options" && h.Status != "ok" {
			t.Errorf("Expected X-Frame-Options to be ok due to frame-ancestors, got %s", h.Status)
		}
	}
}

func TestAnalyzeCSP(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		expected bool // true if has high severity issue
	}{
		{"Strong CSP", "default-src 'self'", false},
		{"Weak unsafe-inline script", "script-src 'unsafe-inline'", true},
		{"Weak wildcard script", "script-src *", true},
		{"Weak default-src eval", "default-src 'unsafe-eval'", true},
		{"Strong style unsafe-inline", "style-src 'unsafe-inline'", false}, // severity low
		{"Weak data URI script", "script-src data:", false}, // severity medium
		{"Backward compatible strict-dynamic", "script-src 'unsafe-inline' 'strict-dynamic' 'nonce-12345'", false}, // severity info
		{"Unsafe strict-dynamic", "script-src 'strict-dynamic' 'unsafe-inline'", true}, // missing nonce, so unsafe-inline is high
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := analyzeCSP(tt.csp)
			hasHigh := false
			for _, issue := range issues {
				if issue.Severity == "high" {
					hasHigh = true
					break
				}
			}
			if hasHigh != tt.expected {
				t.Errorf("analyzeCSP(%q) high severity = %v; want %v", tt.csp, hasHigh, tt.expected)
			}
		})
	}
}

func TestHasSecureFrameAncestors(t *testing.T) {
	tests := []struct {
		name     string
		csp      string
		expected bool
	}{
		{"Valid frame-ancestors", "default-src 'self'; frame-ancestors 'none'", true},
		{"Valid frame-ancestors with space", "default-src 'self'; frame-ancestors 'self' https://example.com", true},
		{"False positive string contains", "default-src 'self'; report-uri /api/frame-ancestors", false},
		{"Wildcard frame-ancestors", "default-src 'self'; frame-ancestors *;", false},
		{"Empty frame-ancestors value", "default-src 'self'; frame-ancestors ;", false},
		{"No frame-ancestors", "default-src 'self'", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSecureFrameAncestors(tt.csp)
			if got != tt.expected {
				t.Errorf("hasSecureFrameAncestors(%q) = %v; want %v", tt.csp, got, tt.expected)
			}
		})
	}
}

func TestAnalyzeCORS_Unknown(t *testing.T) {
	// Khởi tạo client tĩnh đã tự động được gọi qua init() của file service.go

	// Test với URL không kết nối được để ép lỗi kết nối deterministically
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	ts.Close() // Đóng ngay lập tức để ép lỗi connection refused

	result := analyzeCORS(context.Background(), ts.URL)

	if result.Data.Error == "" {
		t.Errorf("Expected CORS analysis to return an error for unreachable host, got none")
	}
}

func TestCountRedirects(t *testing.T) {
	// Giả lập chuỗi redirect: resp -> req -> resp -> req -> resp
	u, _ := url.Parse("https://example.com")
	
	resp1 := &http.Response{
		Request: &http.Request{URL: u},
	}
	req1 := &http.Request{URL: u, Response: resp1}
	resp2 := &http.Response{Request: req1}
	req2 := &http.Request{URL: u, Response: resp2}
	resp3 := &http.Response{Request: req2}

	chain := getRedirectChain(resp3)
	if len(chain)-1 != 2 {
		t.Errorf("Expected 2 redirects, got %d", len(chain)-1)
	}
}

func TestHSTS_TokenParsing(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	// valid max-age, but fake others
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includesubdomains-fake; notpreload")
	
	result := analyzeHeaders(resp, "https")

	for _, h := range result.Headers {
		if h.Name == "Strict-Transport-Security" {
			if !strings.Contains(h.Risk, "includeSubDomains") {
				t.Errorf("Expected Risk to mention missing includeSubDomains, got: %s", h.Risk)
			}
		}
	}
}

func TestHSTS_MaxAgeFake(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	// fake max-age
	resp.Header.Set("Strict-Transport-Security", "max-age-fake=31536000; includeSubDomains")
	
	result := analyzeHeaders(resp, "https")

	for _, h := range result.Headers {
		if h.Name == "Strict-Transport-Security" {
			if h.Status != "danger" {
				t.Errorf("Expected Status danger for max-age-fake, got: %s", h.Status)
			}
			if !strings.Contains(h.Risk, "không hợp lệ") {
				t.Errorf("Expected Risk to mention invalid max-age, got: %s", h.Risk)
			}
		}
	}
}

func TestHSTS_OptionalPreload(t *testing.T) {
	resp := &http.Response{
		Header: make(http.Header),
	}
	// has max-age and includeSubDomains, missing preload
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	
	result := analyzeHeaders(resp, "https")

	for _, h := range result.Headers {
		if h.Name == "Strict-Transport-Security" {
			if h.Status != "ok" {
				t.Errorf("Expected Status ok for missing preload but valid HSTS, got: %s", h.Status)
			}
			if strings.Contains(h.Risk, "Thiếu") {
				t.Errorf("Should not warn about missing preload in Risk text, got: %s", h.Risk)
			}
		}
	}
}

func TestAnalyzeCORS_Probes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT")
		}
	}))
	defer ts.Close()

	// Override noRedirectClient to bypass SSRF protection in test
	originalClient := noRedirectClient
	noRedirectClient = &http.Client{}
	defer func() { noRedirectClient = originalClient }()

	result := analyzeCORS(context.Background(), ts.URL)
	hasDangerousPreflight := false
	hasNullOrigin := false
	for _, issue := range result.Data.Issues {
		if strings.Contains(issue.Description, "Preflight") {
			hasDangerousPreflight = true
		}
		if strings.Contains(issue.Description, "Null Origin") {
			hasNullOrigin = true
		}
	}
	if !hasDangerousPreflight {
		t.Errorf("Expected dangerous preflight issue due to PUT")
	}
	if !hasNullOrigin {
		t.Errorf("Expected null origin issue due to ACAO * for Origin null")
	}
}

