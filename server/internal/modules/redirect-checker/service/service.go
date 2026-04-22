package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"tools.bctechvibe.com/server/internal/modules/redirect-checker/models"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

const (
	MaxRedirects = 10
	MaxBodySize  = 100 * 1024 // 100KB for meta/seo parsing
)

var (
	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+content=['"]?\d+;\s*url=['"]?([^'">\s]+)['"]?[^>]*>`)
	reJSRedirect  = regexp.MustCompile(`(?i)window\.location(?:\.(?:href|replace))?\s*(?:=|\()\s*['"]([^'"]+)['"]`)
	reTitle       = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]+rel=['"]canonical['"][^>]+href=['"]([^'"]+)['"]`)
	reOGTitle     = regexp.MustCompile(`(?i)<meta[^>]+property=['"]og:title['"][^>]+content=['"]([^'"]+)['"]`)
	reOGImage     = regexp.MustCompile(`(?i)<meta[^>]+property=['"]og:image['"][^>]+content=['"]([^'"]+)['"]`)
	reRobots      = regexp.MustCompile(`(?i)<meta[^>]+name=['"]robots['"][^>]+content=['"]([^'"]+)['"]`)

	ErrRateLimited = errors.New("tốc độ yêu cầu quá nhanh")

	// Singleton clients for better connection reuse
	standardClient *http.Client
	insecureClient *http.Client
	clientOnce     sync.Once

	// Rate limit for bypass cache requests (5 requests per 1 minute per IP)
	rateLimitCache = cache.New[string, []time.Time](1000, 5*time.Minute)
	rateLimitMutex sync.Mutex
)

// initClients initializes the singleton HTTP clients.
func initClients() {
	createTransport := func(insecure bool) *http.Transport {
		return &http.Transport{
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: insecure},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}

				ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}

				var safeIP net.IP
				for _, ip := range ips {
					if validator.IsSafeIP(ip) {
						safeIP = ip
						break
					}
				}

				if safeIP == nil {
					return nil, fmt.Errorf("bảo vệ SSRF: không tìm thấy IP an toàn cho %s", host)
				}

				return (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		}
	}

	standardClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: createTransport(false),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	insecureClient = &http.Client{
		Timeout:   10 * time.Second,
		Transport: createTransport(true),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// CheckRateLimit implements a simple sliding window rate limiter for bypass cache requests.
func CheckRateLimit(ip string) error {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	window := 1 * time.Minute
	maxRequests := 5

	history, _ := rateLimitCache.Get(ip)
	var valid []time.Time
	for _, t := range history {
		if now.Sub(t) < window {
			valid = append(valid, t)
		}
	}

	if len(valid) >= maxRequests {
		return ErrRateLimited
	}

	valid = append(valid, now)
	rateLimitCache.Set(ip, valid, 0)
	return nil
}

func normalizeForLoop(rawURL string) string {
	p, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	p.Fragment = ""
	// Normalize query parameters order
	query := p.Query()
	p.RawQuery = query.Encode()
	
	host := strings.ToLower(p.Host)
	path := strings.TrimRight(p.Path, "/")
	scheme := strings.ToLower(p.Scheme)
	
	result := fmt.Sprintf("%s://%s%s", scheme, host, path)
	if p.RawQuery != "" {
		result += "?" + p.RawQuery
	}
	return result
}

// AnalyzeRedirects performs the core logic of following a URL and capturing all hops.
func AnalyzeRedirects(ctx context.Context, req models.RedirectAnalyzeRequest) (*models.RedirectAnalyzeResponse, error) {
	clientOnce.Do(initClients)

	// Create a per-request cookie jar to avoid data leakage between different users
	jar, _ := cookiejar.New(nil)
	
	var base *http.Client
	if req.IgnoreTLSErrors {
		base = insecureClient
	} else {
		base = standardClient
	}

	// Explicitly initialize per-request client to avoid any shared state risks
	client := &http.Client{
		Timeout:       base.Timeout,
		Transport:     base.Transport,
		CheckRedirect: base.CheckRedirect,
		Jar:           jar,
	}

	resp := &models.RedirectAnalyzeResponse{
		Success: true,
	}
	resp.Data.Chain = []models.RedirectHop{}

	currentURL := req.URL
	totalTimeStart := time.Now()
	prevScheme := ""
	
	// Backend Loop Detection
	visitedURLs := make(map[string]bool)

	for step := 1; step <= MaxRedirects; step++ {
		// Use proper normalization for loop detection (Point #3)
		loopKey := normalizeForLoop(currentURL)
		if visitedURLs[loopKey] {
			if len(resp.Data.Chain) > 0 {
				lastIdx := len(resp.Data.Chain) - 1
				resp.Data.Chain[lastIdx].Error = "Phát hiện vòng lặp chuyển hướng vô hạn (Redirect Loop)"
			}
			break
		}
		visitedURLs[loopKey] = true

		// Respect client cancellation explicitly
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		hop, nextURL, bodyHTML, err := performHop(ctx, client, currentURL, req.UserAgent, step)
		
		if hop != nil {
			resp.Data.Chain = append(resp.Data.Chain, *hop)
			
			parsedURL, _ := url.Parse(currentURL)
			if parsedURL != nil {
				if prevScheme == "https" && parsedURL.Scheme == "http" {
					resp.Data.Security.IsHTTPSDowngrade = true
				}
				prevScheme = parsedURL.Scheme
			}
		}

		if err != nil {
			if hop == nil {
				resp.Data.Chain = append(resp.Data.Chain, models.RedirectHop{
					Step:  step,
					URL:   currentURL,
					Error: errutil.TranslateError(err),
				})
			}
			break
		}

		// Check for Meta/JS redirects via Deep Scan
		if req.DeepScan && nextURL == "" && hop != nil && hop.StatusCode == 200 {
			metaURL, statusText := checkMetaRefresh(bodyHTML)
			if metaURL != "" {
				parsedNext, _ := url.Parse(metaURL)
				parsedCurr, _ := url.Parse(currentURL)
				if parsedNext != nil && parsedCurr != nil {
					nextURL = parsedCurr.ResolveReference(parsedNext).String()
					hop.StatusText = statusText
				}
			}
		}

		if step == MaxRedirects && nextURL != "" {
			resp.Data.Performance.TooMany = true
			break
		}

		if nextURL == "" {
			if hop != nil && hop.StatusCode == 200 {
				extractSEO(hop, &resp.Data.SEO, bodyHTML)
			}
			break
		}

		currentURL = nextURL
	}

	resp.Data.Performance.TotalTime = time.Since(totalTimeStart).Milliseconds()
	
	redirectCount := 0
	for _, hop := range resp.Data.Chain {
		if (hop.StatusCode >= 300 && hop.StatusCode < 400) || strings.Contains(hop.StatusText, "Redirect") {
			redirectCount++
		}
	}
	resp.Data.Performance.TotalRedirects = redirectCount

	// Open Redirect check
	if len(resp.Data.Chain) > 1 {
		firstHop := resp.Data.Chain[0]
		lastHop := resp.Data.Chain[len(resp.Data.Chain)-1]
		
		fP, _ := url.Parse(firstHop.URL)
		lP, _ := url.Parse(lastHop.URL)
		
		if fP != nil && lP != nil {
			isExt := fP.Host != lP.Host && !strings.HasSuffix(lP.Host, "."+fP.Host)
			suspiciousParams := []string{"url", "redirect", "next", "goto", "return", "to", "link"}
			query := fP.Query()
			
			hasSuspicious := false
			for _, p := range suspiciousParams {
				val := query.Get(p)
				if val == "" { continue }
				if strings.HasPrefix(val, "//") { val = "https:" + val }
				pURL, _ := url.Parse(val)
				if pURL != nil && pURL.Host != "" && (pURL.Host == lP.Host || strings.HasSuffix(lP.Host, "."+pURL.Host)) {
					hasSuspicious = true
					break
				}
			}

			if isExt && hasSuspicious {
				resp.Data.Security.IsOpenRedirect = true
			}
		}
	}

	return resp, nil
}

func performHop(ctx context.Context, client *http.Client, targetURL string, userAgent string, step int) (*models.RedirectHop, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("URL không hợp lệ: %v", err)
	}

	// Sanitize User-Agent
	userAgent = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' { return -1 }
		return r
	}, userAgent)

	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	var dnsStart, dnsDone, tcpStart, tcpDone, tlsStart, tlsDone, ttfb time.Time
	var serverIP string

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
			if len(dnsInfo.Addrs) > 0 { serverIP = dnsInfo.Addrs[0].IP.String() }
		},
		ConnectStart: func(_, _ string) { tcpStart = time.Now() },
		ConnectDone: func(network, addr string, err error) {
			tcpDone = time.Now()
			if serverIP == "" {
				h, _, _ := net.SplitHostPort(addr)
				serverIP = h
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { ttfb = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	start := time.Now()
	resp, err := client.Do(req)
	
	displayURL := targetURL
	if parsed, err := url.Parse(targetURL); err == nil {
		parsed.User = nil
		displayURL = parsed.String()
	}

	hop := &models.RedirectHop{
		Step:   step,
		URL:    displayURL,
		IP:     serverIP,
		Method: req.Method,
	}

	if resp != nil {
		hop.Protocol = resp.Proto
	} else {
		if p, _ := url.Parse(targetURL); p != nil { hop.Protocol = strings.ToUpper(p.Scheme) }
	}

	if err != nil {
		hop.Error = errutil.TranslateError(err)
		return hop, "", "", err
	}
	defer resp.Body.Close()

	hop.Timings = models.RedirectTimings{
		DNSLookup: func() int64 { if dnsDone.IsZero() { return 0 }; return dnsDone.Sub(dnsStart).Milliseconds() }(),
		TCPConnection: func() int64 { if tcpDone.IsZero() { return 0 }; return tcpDone.Sub(tcpStart).Milliseconds() }(),
		TLSHandshake: func() int64 { if tlsDone.IsZero() { return 0 }; return tlsDone.Sub(tlsStart).Milliseconds() }(),
		TTFB: func() int64 { if ttfb.IsZero() { return 0 }; return ttfb.Sub(start).Milliseconds() }(),
		Total: time.Since(start).Milliseconds(),
	}

	hop.StatusCode = resp.StatusCode
	hop.StatusText = resp.Status

	sensitive := map[string]bool{"server": true, "x-powered-by": true, "via": true}
	hop.Headers = make(map[string][]string)
	for k, v := range resp.Header {
		if !sensitive[strings.ToLower(k)] && !strings.HasPrefix(strings.ToLower(k), "x-internal-") {
			hop.Headers[k] = v
		}
	}

	var bodyHTML string
	// Check Content-Length to avoid reading massive files (Point #4)
	if resp.ContentLength > 0 && resp.ContentLength > int64(MaxBodySize*10) {
		// Just skip reading if it's clearly too big (e.g. > 1MB)
	} else if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
		bodyHTML = string(bodyBytes)
	}

	nextURL := ""
	if isRedirect(resp.StatusCode) {
		if loc := resp.Header.Get("Location"); loc != "" {
			pT, _ := url.Parse(targetURL)
			pL, err := url.Parse(loc)
			if err == nil && pT != nil {
				nextURL = pT.ResolveReference(pL).String()
			} else {
				nextURL = loc
			}
		}
	}

	return hop, nextURL, bodyHTML, nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

func checkMetaRefresh(bodyHTML string) (string, string) {
	if bodyHTML == "" { return "", "" }
	if m := reMetaRefresh.FindStringSubmatch(bodyHTML); len(m) > 1 { return m[1], "200 OK (Meta Refresh)" }
	if m := reJSRedirect.FindStringSubmatch(bodyHTML); len(m) > 1 { return m[1], "200 OK (JS Redirect)" }
	return "", ""
}

func extractSEO(hop *models.RedirectHop, seo *models.SEOAudit, bodyHTML string) {
	if bodyHTML == "" { return }
	if m := reTitle.FindStringSubmatch(bodyHTML); len(m) > 1 { seo.Title = m[1] }
	if m := reCanonical.FindStringSubmatch(bodyHTML); len(m) > 1 { seo.Canonical = m[1] }
	if m := reOGTitle.FindStringSubmatch(bodyHTML); len(m) > 1 { seo.OGTitle = m[1] }
	if m := reOGImage.FindStringSubmatch(bodyHTML); len(m) > 1 { seo.OGImage = m[1] }
	if m := reRobots.FindStringSubmatch(bodyHTML); len(m) > 1 { seo.Robots = m[1] }
}

func ResolveHTTPStatus(err error, ctxErr error) int {
	if ctxErr != nil { return http.StatusGatewayTimeout }
	if errors.Is(err, ErrRateLimited) { return http.StatusTooManyRequests }
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() { return http.StatusGatewayTimeout }
		return http.StatusBadGateway
	}
	return http.StatusInternalServerError
}
