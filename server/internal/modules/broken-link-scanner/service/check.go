package service

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

// ProcessScan kicks off the complete scanning phase
func ProcessScan(ctx context.Context, req models.ScanRequest) (models.ScanData, error) {
	data, validLinks, err := ExtractLinks(req)
	if err != nil {
		return models.ScanData{}, err
	}

	workerCount := req.MaxWorkers
	if workerCount < 5 {
		workerCount = 5
	}
	if workerCount > 50 {
		workerCount = 50
	}

	client := SafeHTTPClient(req.IgnoreTlsErrors, 10*time.Second)

	results := make([]models.ScanResultRow, len(validLinks))
	
	// Create channels
	jobs := make(chan int, len(validLinks))
	var wg sync.WaitGroup

	// Per-host semaphore mapping to prevent hammering single domains
	// Max 5 concurrent requests per host.
	hostSemaphores := &sync.Map{} 

	// Start workers
	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for idx := range jobs {
				select {
				case <-ctx.Done():
					return 
				default:
					results[idx] = checkURL(validLinks[idx], client, hostSemaphores, req.IgnoreTlsErrors, req.BypassCache)
				}
			}
		}(w)
	}

	// Dispatch jobs
	for i := range validLinks {
		jobs <- i
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()

	data.Results = results

	// Compute summaries
	for _, r := range data.Results {
		switch r.StatusClass {
		case "ok":
			data.Summary.Ok++
		case "redirect":
			data.Summary.Redirect++
		case "broken":
			data.Summary.Broken++
		case "blocked":
			data.Summary.Blocked++
		}
	}

	return data, nil
}

type CachedVerdict struct {
	StatusCode    int
	StatusClass   string
	FinalURL      string
	RedirectCount int
	ResponseMs    int64
	ErrorDetail   string
}

func checkURL(asset models.ScanResultRow, client *http.Client, hostSems *sync.Map, ignoreTLS bool, bypassCache bool) models.ScanResultRow {
	cacheKey := BuildCacheKey(asset.FinalURL, ignoreTLS)

	if !bypassCache {
		if cachedItem, _, ok := CacheGet(cacheKey); ok {
			cv := cachedItem.(CachedVerdict)
			asset.StatusCode = cv.StatusCode
			asset.StatusClass = cv.StatusClass
			asset.FinalURL = cv.FinalURL
			asset.RedirectCount = cv.RedirectCount
			asset.ResponseMs = cv.ResponseMs
			asset.Error = cv.ErrorDetail
			return asset
		}
	}

	// Throttle per-host.
	host := ""
	if u, err := url.Parse(asset.FinalURL); err == nil {
		host = u.Host
	}
	if host == "" {
		host = asset.FinalURL
	}
	
	// Ensure the semaphore channel exists
	semVal, _ := hostSems.LoadOrStore(host, make(chan struct{}, 5))
	hostSem := semVal.(chan struct{})

	// Acquire per-host lock
	hostSem <- struct{}{}
	defer func() { <-hostSem }()

	start := time.Now()

	verdict := doFetchWithFallback(asset.FinalURL, client, 0)

	asset.ResponseMs = time.Since(start).Milliseconds()
	asset.StatusCode = verdict.StatusCode
	asset.StatusClass = verdict.StatusClass
	asset.FinalURL = verdict.FinalURL
	asset.RedirectCount = verdict.RedirectCount
	asset.Error = verdict.ErrorDetail

	// Save to Cache
	if asset.StatusClass != "unknown" {
		CacheSet(cacheKey, CachedVerdict{
			StatusCode:    asset.StatusCode,
			StatusClass:   asset.StatusClass,
			FinalURL:      asset.FinalURL,
			RedirectCount: asset.RedirectCount,
			ResponseMs:    asset.ResponseMs,
			ErrorDetail:   asset.Error,
		})
	}

	return asset
}

func doFetchWithFallback(url string, client *http.Client, redirectDepth int) CachedVerdict {
	if redirectDepth >= 5 {
		return CachedVerdict{FinalURL: url, RedirectCount: redirectDepth, StatusCode: -1, StatusClass: "broken", ErrorDetail: "Too many redirects"}
	}

	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return CachedVerdict{FinalURL: url, RedirectCount: redirectDepth, StatusCode: -1, StatusClass: "broken", ErrorDetail: "Parse Error"}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BCTechVibe-Scanner/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	
	shouldFallback := false
	
	if err != nil {
		shouldFallback = matchTransportFallbackError(err)
	} else {
		defer resp.Body.Close()
		// If HEAD returned explicitly weird/forbidden codes, fallback because CDN might be strict.
		if resp.StatusCode == 405 || resp.StatusCode == 403 || resp.StatusCode == 501 {
			shouldFallback = true
		}
	}

	// EXECUTE FALLBACK FETCH
	if shouldFallback {
		reqGet, _ := http.NewRequest("GET", url, nil)
		reqGet.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BCTechVibe-Scanner/1.0")
		reqGet.Header.Set("Accept", "*/*")
		
		respGet, errGet := client.Do(reqGet)
		if errGet == nil {
			defer respGet.Body.Close()
			return evaluateFinalStatus(respGet, client, redirectDepth, url)
		} else {
			// If GET also completely failed, report it.
			return parseRequestError(errGet, url, redirectDepth)
		}
	}

	if err != nil {
		// If it failed and wasn't eligible for fallback
		return parseRequestError(err, url, redirectDepth)
	}

	return evaluateFinalStatus(resp, client, redirectDepth, url)
}

func evaluateFinalStatus(resp *http.Response, client *http.Client, redirectDepth int, initialURL string) CachedVerdict {
	// Status Evaluation
	code := resp.StatusCode
	
	// Handle 3xx Redirects
	if code >= 300 && code <= 308 && code != 304 {
		loc, err := resp.Location()
		if err != nil {
			return CachedVerdict{FinalURL: initialURL, RedirectCount: redirectDepth, StatusCode: code, StatusClass: "broken", ErrorDetail: "Missing Location Header on 3xx"}
		}
		
		target := loc.String()
		// Go recursive!
		v := doFetchWithFallback(target, client, redirectDepth+1)
		
		// If final is broken, then the WHOLE CHAIN is mapped as broken! 
		// Except if the final was OK, then mark it as redirect
		if v.StatusClass == "ok" {
			v.StatusClass = "redirect" 
		}
		// Notice how `v.StatusCode` isn't overridden if you want to keep final. BUT we need to report final code.
		return v
	}

	// Final Status Classifier
	class := "ok"
	if code >= 200 && code < 300 {
		class = "ok"
	} else if code == 403 || code == 401 { // Some resources strictly block
		class = "blocked" 
	} else if code >= 400 {
		class = "broken"
	} else {
		class = "broken" // 500s 
	}

	return CachedVerdict{
		StatusCode:    code,
		StatusClass:   class,
		FinalURL:      initialURL,
		RedirectCount: redirectDepth,
	}
}

// matchTransportFallbackError validates errors.Is / As rules before using substring matching
func matchTransportFallbackError(err error) bool {
	// 1. Unwrap
	errInner := err
	var urler *url.Error
	if errors.As(err, &urler) {
		errInner = urler.Err
	}

	// 2. Strong types priority
	if errors.Is(errInner, io.EOF) {
		return true
	}
	
	// Type casting 
	var netErr net.Error
	if errors.As(errInner, &netErr) {
		if netErr.Timeout() { 
			return false // No point GET-fetching if we are truly timed-out, it's a dead end.
		}
		// TCP reset is acceptable to re-try via GET normally
	}
	
	msg := strings.ToLower(errInner.Error())
	// 3. Known platform WAF string edge cases fallback
	if strings.Contains(msg, "connection reset by peer") || strings.Contains(msg, "stream error") {
		return true
	}

	return false
}

func parseRequestError(err error, urlStr string, redirects int) CachedVerdict {
	return CachedVerdict{
		FinalURL:      urlStr,
		RedirectCount: redirects,
		StatusCode:    -1, // Represent failure on transport layer
		StatusClass:   "broken",
		ErrorDetail:   err.Error(),
	}
}
