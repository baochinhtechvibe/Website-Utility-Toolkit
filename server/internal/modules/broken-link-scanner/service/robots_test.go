package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRobotsChecker_CacheOriginAndPort(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\nDisallow: /admin"))
	}))
	defer ts.Close()

	client := ts.Client()
	rc := NewRobotsChecker(client, "TestBot", nil)

	// 1. Test fetching from httptest Server with specific port
	allowed := rc.IsAllowed(ts.URL + "/public")
	assert.True(t, allowed)
	assert.Equal(t, 1, callCount)

	// 2. Fetch again, should use cache (callCount remains 1)
	allowed2 := rc.IsAllowed(ts.URL + "/public/2")
	assert.True(t, allowed2)
	assert.Equal(t, 1, callCount)

	// 3. Test Disallowed
	disallowed := rc.IsAllowed(ts.URL + "/admin/login")
	assert.False(t, disallowed)
	assert.Equal(t, 1, callCount)
}

func TestRobotsChecker_4xxAllow(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404) // e.g. Not Found
	}))
	defer ts.Close()

	rc := NewRobotsChecker(ts.Client(), "TestBot", nil)
	
	// 404 should mean full allowance
	assert.True(t, rc.IsAllowed(ts.URL+"/secret"))
}

func TestRobotsChecker_5xxAnd429Block(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503) // e.g. Service Unavailable
	}))
	defer ts.Close()

	rc := NewRobotsChecker(ts.Client(), "TestBot", nil)
	
	// 500+ should result in error, thus IsAllowed returns false
	assert.False(t, rc.IsAllowed(ts.URL+"/public"))
}

func TestRobotsChecker_CrawlDelayPerHost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("User-agent: *\nCrawl-delay: 1"))
	}))
	defer ts.Close()

	rc := NewRobotsChecker(ts.Client(), "TestBot", nil)
	
	ctx := context.Background()
	
	// Request 1
	start := time.Now()
	err := rc.WaitCrawlDelay(ctx, ts.URL+"/1", 0, true)
	assert.NoError(t, err)
	// Should not wait on first request
	assert.Less(t, time.Since(start), 100*time.Millisecond)

	// Request 2
	start2 := time.Now()
	err = rc.WaitCrawlDelay(ctx, ts.URL+"/2", 0, true)
	assert.NoError(t, err)
	// Should have waited ~1 second
	assert.GreaterOrEqual(t, time.Since(start2), 900*time.Millisecond)
}
