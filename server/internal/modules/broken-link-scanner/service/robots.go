package service

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/temoto/robotstxt"
)

const maxCrawlDelay = 10 * time.Second

type CachedRobots struct {
	Data  *robotstxt.RobotsData
	Error error
}

type RobotsChecker struct {
	// Cache: origin → *CachedRobots
	cacheMu sync.RWMutex
	cache   map[string]*CachedRobots

	// Per-origin in-flight fetch deduplication
	fetchMu  sync.Mutex
	inflight map[string]*robotsFetch

	// Per-origin rate limiting
	rateMu     sync.Mutex
	hostMutex  map[string]*sync.Mutex
	lastAccess map[string]time.Time

	client     *http.Client
	agent      string
	progressFn ProgressFn
}

// robotsFetch represents an in-flight or completed robots.txt fetch for one origin.
type robotsFetch struct {
	wg  sync.WaitGroup
	res *CachedRobots
}

func NewRobotsChecker(client *http.Client, agent string, fn ProgressFn) *RobotsChecker {
	if agent == "" {
		agent = "BCTechVibeBot"
	}
	return &RobotsChecker{
		cache:      make(map[string]*CachedRobots),
		inflight:   make(map[string]*robotsFetch),
		hostMutex:  make(map[string]*sync.Mutex),
		lastAccess: make(map[string]time.Time),
		client:     client,
		agent:      agent,
		progressFn: fn,
	}
}

func (rc *RobotsChecker) getOrigin(targetURL string) string {
	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}
	// u.Host includes port (e.g. "example.com:8443"), which is correct for cache keying.
	if u.Host == "" || u.Scheme == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// GetRobots fetches (or returns cached) robots.txt for the given URL's origin.
// It uses a singleflight-style pattern so only one goroutine fetches per origin at a time,
// without holding a lock during network I/O.
func (rc *RobotsChecker) GetRobots(targetURL string) (*robotstxt.RobotsData, error) {
	origin := rc.getOrigin(targetURL)
	if origin == "" {
		return nil, nil
	}

	// Fast path: already cached
	rc.cacheMu.RLock()
	cached, exists := rc.cache[origin]
	rc.cacheMu.RUnlock()
	if exists {
		return cached.Data, cached.Error
	}

	// Slow path: acquire per-origin in-flight slot
	rc.fetchMu.Lock()
	// Double check under fetchMu before starting network
	rc.cacheMu.RLock()
	cached, exists = rc.cache[origin]
	rc.cacheMu.RUnlock()
	if exists {
		rc.fetchMu.Unlock()
		return cached.Data, cached.Error
	}

	if f, inFlight := rc.inflight[origin]; inFlight {
		// Another goroutine is already fetching this origin – wait for it
		rc.fetchMu.Unlock()
		f.wg.Wait()
		return f.res.Data, f.res.Error
	}

	// We're the first goroutine – register in-flight fetch
	f := &robotsFetch{}
	f.wg.Add(1)
	rc.inflight[origin] = f
	rc.fetchMu.Unlock()

	// Do the network call WITHOUT any lock held
	result := rc.fetchRobots(origin)

	// Store in cache and signal waiters
	rc.cacheMu.Lock()
	rc.cache[origin] = result
	rc.cacheMu.Unlock()

	f.res = result
	f.wg.Done()

	// Remove from in-flight map
	rc.fetchMu.Lock()
	delete(rc.inflight, origin)
	rc.fetchMu.Unlock()

	return result.Data, result.Error
}

func (rc *RobotsChecker) fetchRobots(origin string) *CachedRobots {
	robotsURL := origin + "/robots.txt"

	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return &CachedRobots{Error: err}
	}
	req.Header.Set("User-Agent", rc.agent)

	resp, err := rc.client.Do(req)
	if err != nil {
		return &CachedRobots{Error: err}
	}
	defer resp.Body.Close()

	// 5xx and 429: server-side error → block as a precaution
	if resp.StatusCode >= 500 || resp.StatusCode == 429 {
		return &CachedRobots{Error: errors.New("server error or rate limit fetching robots.txt")}
	}

	// 4xx (e.g. 404, 403): no robots.txt restrictions → allow all
	if resp.StatusCode >= 400 {
		return &CachedRobots{Data: nil, Error: nil}
	}

	data, err := robotstxt.FromResponse(resp)
	if err != nil {
		return &CachedRobots{Error: err}
	}
	return &CachedRobots{Data: data, Error: nil}
}

func (rc *RobotsChecker) IsAllowed(targetURL string) bool {
	data, err := rc.GetRobots(targetURL)
	if err != nil {
		return false // 5xx/429 → block
	}
	if data == nil {
		return true // 4xx or no robots.txt → allow
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return true
	}
	group := data.FindGroup(rc.agent)
	return group.Test(u.Path)
}

func (rc *RobotsChecker) GetCrawlDelay(targetURL string) time.Duration {
	data, _ := rc.GetRobots(targetURL)
	if data == nil {
		return 0
	}
	group := data.FindGroup(rc.agent)
	return group.CrawlDelay
}

// WaitCrawlDelay enforces a per-origin crawl delay (real rate-limiting, not per-worker sleep).
// Both ExtractLinks and checkURL call this so they share the same per-host last-access timestamp.
func (rc *RobotsChecker) WaitCrawlDelay(ctx context.Context, targetURL string, explicitDelay int, respectRobots bool) error {
	origin := rc.getOrigin(targetURL)
	if origin == "" {
		return nil
	}

	delay := time.Duration(0)
	if explicitDelay > 0 {
		delay = time.Duration(explicitDelay) * time.Millisecond
	} else if respectRobots {
		delay = rc.GetCrawlDelay(targetURL)
	}

	if delay <= 0 {
		return nil
	}

	// Enforce global cap consistently
	if delay > maxCrawlDelay {
		delay = maxCrawlDelay
	}

	// Retrieve (or create) the per-origin mutex
	rc.rateMu.Lock()
	hm, exists := rc.hostMutex[origin]
	if !exists {
		hm = &sync.Mutex{}
		rc.hostMutex[origin] = hm
	}
	rc.rateMu.Unlock()

	// Serialize access per origin so concurrent workers queue up instead of all sleeping at once
	hm.Lock()
	now := time.Now()
	last := rc.lastAccess[origin]
	nextAllowed := last.Add(delay)

	var waitTime time.Duration
	if now.Before(nextAllowed) {
		waitTime = nextAllowed.Sub(now)
		rc.lastAccess[origin] = nextAllowed
	} else {
		rc.lastAccess[origin] = now
	}
	hm.Unlock()

	if waitTime > 0 {
		select {
		case <-time.After(waitTime):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
