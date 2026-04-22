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
	"tools.bctechvibe.com/server/internal/platform/errutil"
)

// ProcessScan kicks off the complete scanning phase
func ProcessScan(ctx context.Context, req models.ScanRequest) (models.ScanData, error) {
	data, validLinks, err := ExtractLinks(ctx, req)
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

	client := SafeHTTPClient(req.IgnoreTlsErrors)

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
					results[idx] = checkURL(ctx, validLinks[idx], client, hostSemaphores, req.IgnoreTlsErrors, req.BypassCache)
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
		case "timeout":
			data.Summary.Timeout++
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

func checkURL(ctx context.Context, asset models.ScanResultRow, client *http.Client, hostSems *sync.Map, ignoreTLS bool, bypassCache bool) models.ScanResultRow {
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
	
	// Point #11: Initialize visited map for loop detection
	visited := make(map[string]bool)
	verdict := doFetchWithFallback(ctx, asset.FinalURL, client, 0, visited)

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

func doFetchWithFallback(ctx context.Context, urlStr string, client *http.Client, redirectDepth int, visited map[string]bool) CachedVerdict {
	if redirectDepth >= 5 {
		return CachedVerdict{FinalURL: urlStr, RedirectCount: redirectDepth, StatusCode: -1, StatusClass: "broken", ErrorDetail: "Quá nhiều bước chuyển hướng (5+)"}
	}

	// Loop Detection (GEMINI Rule #11)
	normalizedURL := normalizeForLoop(urlStr)
	if visited[normalizedURL] {
		return CachedVerdict{FinalURL: urlStr, RedirectCount: redirectDepth, StatusCode: -1, StatusClass: "broken", ErrorDetail: "Phát hiện vòng lặp chuyển hướng (Redirect Loop)"}
	}
	visited[normalizedURL] = true

	req, err := http.NewRequestWithContext(ctx, "HEAD", urlStr, nil)
	if err != nil {
		return CachedVerdict{FinalURL: urlStr, RedirectCount: redirectDepth, StatusCode: -1, StatusClass: "broken", ErrorDetail: "Lỗi phân tích URL"}
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
		reqGet, _ := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
		reqGet.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BCTechVibe-Scanner/1.0")
		reqGet.Header.Set("Accept", "*/*")
		
		respGet, errGet := client.Do(reqGet)
		if errGet == nil {
			defer respGet.Body.Close()
			return evaluateFinalStatus(ctx, respGet, client, redirectDepth, urlStr, visited)
		} else {
			// If GET also completely failed, report it.
			return parseRequestError(errGet, urlStr, redirectDepth)
		}
	}

	if err != nil {
		// If it failed and wasn't eligible for fallback
		return parseRequestError(err, urlStr, redirectDepth)
	}

	return evaluateFinalStatus(ctx, resp, client, redirectDepth, urlStr, visited)
}

func evaluateFinalStatus(ctx context.Context, resp *http.Response, client *http.Client, redirectDepth int, initialURL string, visited map[string]bool) CachedVerdict {
	// Status Evaluation
	code := resp.StatusCode
	
	// Handle 3xx Redirects
	if code >= 300 && code <= 308 && code != 304 {
		loc, err := resp.Location()
		if err != nil {
			return CachedVerdict{FinalURL: initialURL, RedirectCount: redirectDepth, StatusCode: code, StatusClass: "broken", ErrorDetail: "Thiếu header Location khi redirect"}
		}
		
		target := loc.String()
		// Go recursive!
		v := doFetchWithFallback(ctx, target, client, redirectDepth+1, visited)
		
		// Logic: Nếu trang đích cuối cùng hoạt động tốt (ok) hoặc bị chặn (blocked), 
		// ta hiển thị mã HTTP của bước nhảy ĐẦU TIÊN (301, 302...) 
		// để người dùng biết loại chuyển hướng (GEMINI Issue #3).
		if v.StatusClass == "ok" || v.StatusClass == "blocked" {
			v.StatusClass = "redirect"
			v.StatusCode = code 
		}
		return v
	}

	// Final Status Classifier
	class := "ok"
	if code >= 200 && code < 300 {
		class = "ok"
	} else if code == 403 || code == 401 { // Some resources strictly block
		class = "blocked" 
	} else if code >= 400 && code < 500 {
		class = "broken" // Client error
	} else if code >= 500 {
		class = "broken" // Server error
	} else {
		class = "broken" // Catch-all for 1xx or invalid codes
	}

	return CachedVerdict{
		StatusCode:    code,
		StatusClass:   class,
		FinalURL:      initialURL,
		RedirectCount: redirectDepth,
	}
}


func normalizeForLoop(rawURL string) string {
	p, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	p.Fragment = "" // Ignore anchor
	host := strings.ToLower(p.Host)
	path := strings.TrimRight(p.Path, "/")
	result := strings.ToLower(p.Scheme) + "://" + host + path
	if p.RawQuery != "" {
		result += "?" + p.RawQuery
	}
	return result
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
	statusClass := "broken"
	
	// Better timeout check (GEMINI Rule #42)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		statusClass = "timeout"
	}

	return CachedVerdict{
		FinalURL:      urlStr,
		RedirectCount: redirects,
		StatusCode:    -1, // Represent failure on transport layer
		StatusClass:   statusClass,
		ErrorDetail:   errutil.TranslateError(err),
	}
}
