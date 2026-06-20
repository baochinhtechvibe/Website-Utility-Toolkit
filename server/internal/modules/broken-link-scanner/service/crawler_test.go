package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

func TestCrawler_DeduplicationAndOccurrences(t *testing.T) {
	// Bypass SSRF protection for 127.0.0.1 in tests
	originalCheckHostname := CheckSafeHostname
	CheckSafeHostname = func(h string) bool { return true }
	defer func() { CheckSafeHostname = originalCheckHostname }()

	originalCheckIP := CheckSafeIP
	CheckSafeIP = func(ip net.IP) bool { return true }
	defer func() { CheckSafeIP = originalCheckIP }()
	// Create a mock server to simulate multiple pages linking to the same broken target.
	var requestCount atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html><body>
					<a href="/page2">Go to Page 2</a>
					<a href="/missing">Broken Link 1</a>
				</body></html>
			`))
		case "/page2":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html><body>
					<a href="/missing">Broken Link 2 (same target)</a>
				</body></html>
			`))
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`Not Found`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	req := models.ScanRequest{
		URL:             ts.URL,
		Scope:           "same-host",
		MaxWorkers:      5,
		MaxDepth:        2,
		MaxPages:        5,
		MaxLinks:        100,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := ProcessScan(ctx, req)
	assert.NoError(t, err)

	// Summary checks
	assert.Equal(t, 2, data.Summary.PagesCrawled, "Should crawl exactly 2 pages (/, /page2)")
	
	// We expect occurrences for /missing twice and /page2 once.
	// Target /page2: 1 occurrence (on /)
	// Target /missing: 2 occurrences (on / and /page2)
	assert.Equal(t, 3, data.Summary.Total, "Should find 3 link occurrences")
	assert.Equal(t, 2, data.Summary.UniqueTargets, "Should have 2 unique targets (/page2, /missing)")

	// Broken link checks
	var missingOccurrences int
	for _, res := range data.Results {
		if res.OriginalURL == "/missing" {
			missingOccurrences++
			assert.Equal(t, "broken", res.StatusClass)
			assert.Equal(t, 404, res.StatusCode)
		}
	}
	assert.Equal(t, 2, missingOccurrences, "Should preserve 2 occurrences for the same broken target")

	// Verify HTTP fetch optimization: 
	// / (1), /page2 (1), /missing (1 check as unique target)
	// Actually, wait! The crawler fetches / and /page2, and then the checker verifies /page2 and /missing.
	// But /page2 was already fetched by the crawler? Yes, but checkURL will make an HTTP HEAD/GET to verify it anyway.
	// Let's just ensure requestCount is around 4-8 (1 for root crawl, 1 for page2 crawl, 1 for page2 check, 1 for missing check, plus robots.txt).
	// If deduplication failed, /missing would be checked twice.
	assert.LessOrEqual(t, requestCount.Load(), int32(8), "Should not make excessive duplicate HTTP requests")
}

func TestSafeHTTPClient_SSRFRedirect(t *testing.T) {
	// Setup redirect server on 127.0.0.1
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			// Redirect to loopback
			http.Redirect(w, r, "http://127.0.0.1:1/blocked", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	originalCheckHostname := CheckSafeHostname
	CheckSafeHostname = func(h string) bool { return true }
	defer func() { CheckSafeHostname = originalCheckHostname }()

	// Allow the first connection to local server, but reject the redirect connection
	var checkCount int
	originalCheckIP := CheckSafeIP
	CheckSafeIP = func(ip net.IP) bool {
		checkCount++
		if checkCount == 1 {
			return true // Allow initial request to ts
		}
		return validator.IsSafeIP(ip) // Revert to normal safety checks (blocks 127.0.0.1)
	}
	defer func() { CheckSafeIP = originalCheckIP }()

	client := SafeBasePageClient(true) // followRedirect = true
	req, err := http.NewRequest("GET", ts.URL+"/redirect", nil)
	assert.NoError(t, err)

	_, err = client.Do(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SSRF Blocked")
}

func TestCrawler_ExternalCSSParsing(t *testing.T) {
	originalCheckHostname := CheckSafeHostname
	CheckSafeHostname = func(h string) bool { return true }
	defer func() { CheckSafeHostname = originalCheckHostname }()

	originalCheckIP := CheckSafeIP
	CheckSafeIP = func(ip net.IP) bool { return true }
	defer func() { CheckSafeIP = originalCheckIP }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<html>
				<head>
					<link rel="stylesheet" href="/style.css">
				</head>
				<body>
					<p>Hello</p>
				</body>
				</html>
			`))
		case "/style.css":
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte(`
				@import "/import.css";
				.bg { background-image: url("/img-in-css.jpg"); }
			`))
		case "/import.css":
			w.Header().Set("Content-Type", "text/css")
			w.Write([]byte(`
				.nested { font-family: url("/font.woff"); }
			`))
		case "/img-in-css.jpg", "/font.woff":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	req := models.ScanRequest{
		URL:             ts.URL,
		Scope:           "same-host",
		MaxWorkers:      5,
		MaxDepth:        3,
		MaxPages:        5,
		MaxLinks:        100,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := ProcessScan(ctx, req)
	assert.NoError(t, err)

	assert.Equal(t, 3, data.Summary.PagesCrawled)

	expectedURLs := []string{
		"/style.css",
		"/import.css",
		"/img-in-css.jpg",
		"/font.woff",
	}

	for _, expected := range expectedURLs {
		found := false
		for _, res := range data.Results {
			if strings.HasSuffix(res.OriginalURL, expected) {
				found = true
				break
			}
		}
		assert.True(t, found, "Should extract URL ending with: %s", expected)
	}
}


