package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/redirect/models"
)

const MaxRedirects = 10

var (
	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+content=['"]?\d+;\s*url=['"]?([^'">\s]+)['"]?[^>]*>`)
	reJSRedirect  = regexp.MustCompile(`(?i)window\.location\.(href|replace)\s*=?\s*['"]([^'"]+)['"]`)
	reTitle       = regexp.MustCompile(`(?i)<title>(.*?)</title>`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]+rel=['"]canonical['"][^>]+href=['"]([^'"]+)['"]`)
	reOGTitle     = regexp.MustCompile(`(?i)<meta[^>]+property=['"]og:title['"][^>]+content=['"]([^'"]+)['"]`)
	reRobots      = regexp.MustCompile(`(?i)<meta[^>]+name=['"]robots['"][^>]+content=['"]([^'"]+)['"]`)
)

func isPrivateIP(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	// AWS Metadata IP
	if ip.String() == "169.254.169.254" {
		return true
	}
	return false
}

// AnalyzeRedirects performs the core logic of following a URL and capturing all hops.
func AnalyzeRedirects(ctx context.Context, req models.RedirectAnalyzeRequest) (*models.RedirectAnalyzeResponse, error) {
	resp := &models.RedirectAnalyzeResponse{
		Success: true,
	}
	resp.Data.Chain = []models.RedirectHop{}

	currentURL := req.URL
	if !strings.HasPrefix(currentURL, "http://") && !strings.HasPrefix(currentURL, "https://") {
		currentURL = "http://" + currentURL
	}

	jar, _ := cookiejar.New(nil)

	if req.IgnoreTLSErrors {
		log.Warn().Str("url", currentURL).Msg("TLS certificate verification disabled by user request")
	}

	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Do not follow redirects automatically. We want to capture the response and stop.
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: req.IgnoreTLSErrors},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.LookupIP(host)
				if err != nil {
					return nil, err
				}
				for _, ip := range ips {
					if isPrivateIP(ip) {
						return nil, fmt.Errorf("SSRF Protection: blocked connection to private IP %s", ip.String())
					}
				}
				// Use the first resolved non-private IP
				return (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
			},
		},
	}

	totalTimeStart := time.Now()
	chainWasHTTPS := false

	for step := 1; step <= MaxRedirects; step++ {
		hop, nextURL, bodyHTML, err := performHop(ctx, client, currentURL, req.UserAgent, step)
		
		if hop != nil {
			resp.Data.Chain = append(resp.Data.Chain, *hop)
			
			// Security checks
			parsedURL, _ := url.Parse(currentURL)
			if parsedURL != nil && parsedURL.Scheme == "https" {
				chainWasHTTPS = true
			}
			if chainWasHTTPS && parsedURL != nil && parsedURL.Scheme == "http" {
				resp.Data.Security.IsHTTPSDowngrade = true
			}
		}

		if err != nil {
			// Add error hop if we couldn't even make the request
			if hop == nil {
				resp.Data.Chain = append(resp.Data.Chain, models.RedirectHop{
					Step:  step,
					URL:   currentURL,
					Error: err.Error(),
				})
			}
			break
		}

		if nextURL == "" {
			// We have reached the final destination (no more redirects)
			if req.DeepScan && hop != nil && hop.StatusCode == 200 {
				metaRedirect := checkMetaRefresh(hop, bodyHTML)
				if metaRedirect != "" {
					parsedNext, _ := url.Parse(metaRedirect)
					parsedCurr, _ := url.Parse(currentURL)
					if parsedNext != nil && parsedCurr != nil {
						nextURL = parsedCurr.ResolveReference(parsedNext).String()
					}
				}
			}
			
			if nextURL == "" {
				if hop != nil && hop.StatusCode == 200 {
					extractSEO(hop, &resp.Data.SEO, bodyHTML)
				}
				break
			}
		}

		currentURL = nextURL

		if step == MaxRedirects {
			resp.Data.Performance.TooMany = true
			break
		}
	}

	totalTime := time.Since(totalTimeStart).Milliseconds()
	resp.Data.Performance.TotalTime = totalTime
	
	// Better TotalRedirects logic
	redirectCount := 0
	if len(resp.Data.Chain) > 1 {
		for i := 0; i < len(resp.Data.Chain)-1; i++ {
			if resp.Data.Chain[i].Error == "" {
				redirectCount++
			}
		}
	}
	resp.Data.Performance.TotalRedirects = redirectCount

	// Simple Open Redirect check: if domain changed significantly and not just subdomain (heuristic)
	if len(resp.Data.Chain) > 1 {
		firstParsed, _ := url.Parse(resp.Data.Chain[0].URL)
		lastParsed, _ := url.Parse(resp.Data.Chain[len(resp.Data.Chain)-1].URL)
		if firstParsed != nil && lastParsed != nil {
			if !strings.HasSuffix(lastParsed.Host, firstParsed.Host) && lastParsed.Host != firstParsed.Host {
				if strings.Contains(firstParsed.RawQuery, lastParsed.Host) {
					resp.Data.Security.IsOpenRedirect = true
				}
			}
		}
	}

	return resp, nil
}

func performHop(ctx context.Context, client *http.Client, targetURL string, userAgent string, step int) (*models.RedirectHop, string, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, "", "", fmt.Errorf("invalid URL: %v", err)
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	var dnsStart, dnsDone, tcpStart, tcpDone, tlsStart, tlsDone, ttfb time.Time
	var serverIP string

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(dnsInfo httptrace.DNSDoneInfo) {
			dnsDone = time.Now()
			if len(dnsInfo.Addrs) > 0 {
				serverIP = dnsInfo.Addrs[0].IP.String()
			}
		},
		ConnectStart: func(_, _ string) { tcpStart = time.Now() },
		ConnectDone: func(network, addr string, err error) {
			tcpDone = time.Now()
			if serverIP == "" {
				host, _, _ := net.SplitHostPort(addr)
				serverIP = host
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		GotFirstResponseByte: func() { ttfb = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	start := time.Now()
	resp, err := client.Do(req)
	
	// If there's an error, we still want to record the hop if possible
	hop := &models.RedirectHop{
		Step:     step,
		URL:      targetURL,
		IP:       serverIP,
		Method:   req.Method,
	}

	if resp != nil {
		hop.Protocol = resp.Proto
	} else {
		if parsed, _ := url.Parse(targetURL); parsed != nil {
			hop.Protocol = strings.ToUpper(parsed.Scheme)
		}
	}

	if err != nil {
		hop.Error = err.Error()
		// Return hop and error
		return hop, "", "", err
	}
	defer resp.Body.Close()

	// Calculate timings
	totalDuration := time.Since(start).Milliseconds()
	var dnsLookup, tcpConn, tlsHandshake, ttfbDuration int64

	if !dnsDone.IsZero() && !dnsStart.IsZero() {
		dnsLookup = dnsDone.Sub(dnsStart).Milliseconds()
	}
	if !tcpDone.IsZero() && !tcpStart.IsZero() {
		tcpConn = tcpDone.Sub(tcpStart).Milliseconds()
	}
	if !tlsDone.IsZero() && !tlsStart.IsZero() {
		tlsHandshake = tlsDone.Sub(tlsStart).Milliseconds()
	}
	if !ttfb.IsZero() {
		ttfbDuration = ttfb.Sub(start).Milliseconds()
	}

	hop.Timings = models.RedirectTimings{
		DNSLookup:     dnsLookup,
		TCPConnection: tcpConn,
		TLSHandshake:  tlsHandshake,
		TTFB:          ttfbDuration,
		Total:         totalDuration,
	}

	hop.StatusCode = resp.StatusCode
	hop.StatusText = resp.Status

	hop.Headers = make(map[string][]string)
	for k, v := range resp.Header {
		hop.Headers[k] = v
	}

	// Read up to 100KB of body for meta/seo directly into a string
	var bodyHTML string
	bodyBytes, errRead := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if errRead != nil {
		log.Warn().Err(errRead).Str("url", targetURL).Msg("Failed to read HTML body completely")
	}
	if len(bodyBytes) > 0 && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		bodyHTML = string(bodyBytes)
	}

	nextURL := ""
	if isRedirect(resp.StatusCode) {
		loc := resp.Header.Get("Location")
		if loc != "" {
			// Resolve relative locations
			parsedTarget, _ := url.Parse(targetURL)
			parsedLoc, err := url.Parse(loc)
			if err == nil && parsedTarget != nil {
				nextURL = parsedTarget.ResolveReference(parsedLoc).String()
			} else {
				nextURL = loc // Fallback
			}
		}
	}

	return hop, nextURL, bodyHTML, nil
}

func isRedirect(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// checkMetaRefresh looks for <meta http-equiv="refresh" content="...;url=..."> in the HTML body
func checkMetaRefresh(hop *models.RedirectHop, bodyHTML string) string {
	if bodyHTML == "" {
		return ""
	}

	matches := reMetaRefresh.FindStringSubmatch(bodyHTML)
	if len(matches) > 1 {
		hop.StatusText = "200 OK (Meta Refresh)"
		return matches[1]
	}

	matchesJS := reJSRedirect.FindStringSubmatch(bodyHTML)
	if len(matchesJS) > 2 {
		hop.StatusText = "200 OK (JS Redirect)"
		return matchesJS[2]
	}
	
	return ""
}

// extractSEO parses basic SEO meta tags from HTML
func extractSEO(hop *models.RedirectHop, seo *models.SEOAudit, bodyHTML string) {
	if bodyHTML == "" {
		return
	}

	if m := reTitle.FindStringSubmatch(bodyHTML); len(m) > 1 {
		seo.Title = m[1]
	}
	if m := reCanonical.FindStringSubmatch(bodyHTML); len(m) > 1 {
		seo.Canonical = m[1]
	}
	if m := reOGTitle.FindStringSubmatch(bodyHTML); len(m) > 1 {
		seo.OGTitle = m[1]
	}
	if m := reRobots.FindStringSubmatch(bodyHTML); len(m) > 1 {
		seo.Robots = m[1]
	}
}
