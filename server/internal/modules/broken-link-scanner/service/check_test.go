package service

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

func TestHEADFallback(t *testing.T) {
	// Mock Server 
	// Drops HEAD with 403 Forbidden
	// Serves GET with 200 OK
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		
		if r.Method == "GET" {
			w.WriteHeader(http.StatusOK)
			return
		}
	}))
	defer ts.Close()

	client := SafeHTTPClient(false, 3*time.Second)
	hostSems := &sync.Map{} 
	
	asset := models.ScanResultRow{
		FinalURL: ts.URL,
	}

	result := checkURL(asset, client, hostSems, false, true)

	// Since HEAD fallback intercepts the 403 and attempts a GET which succeeds...
	assert.Equal(t, 200, result.StatusCode)
	assert.Equal(t, "ok", result.StatusClass)
}

func TestBrokenRedirectChain(t *testing.T) {
	// Client tries to get /redirect
	// Server responds 301 pointing to /broken
	// /broken responds 404
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/broken", http.StatusMovedPermanently)
			return
		}
		if r.URL.Path == "/broken" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}))
	defer ts.Close()

	client := SafeHTTPClient(false, 2*time.Second)
	hostSems := &sync.Map{} 

	asset := models.ScanResultRow{
		FinalURL: ts.URL + "/redirect",
	}

	result := checkURL(asset, client, hostSems, false, true)

	assert.Equal(t, 404, result.StatusCode)
	assert.Equal(t, "broken", result.StatusClass)
	assert.Equal(t, 1, result.RedirectCount) 
}
