package service

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/website-speed-test/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

var (
	browserAllocCtx    context.Context
	browserAllocCancel context.CancelFunc
	rootBrowserCtx     context.Context
	rootBrowserCancel  context.CancelFunc
	browserMu          sync.Mutex
)

func getRootBrowserContext() (context.Context, error) {
	browserMu.Lock()
	defer browserMu.Unlock()

	if rootBrowserCtx == nil || rootBrowserCtx.Err() != nil {
		if rootBrowserCancel != nil {
			rootBrowserCancel()
		}
		if browserAllocCancel != nil {
			browserAllocCancel()
		}

		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", "new"),
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-background-networking", true),
			chromedp.Flag("disable-default-apps", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-sync", true),
			chromedp.Flag("disable-translate", true),
			chromedp.Flag("metrics-recording-only", true),
			chromedp.Flag("mute-audio", true),
			chromedp.Flag("no-first-run", true),
			chromedp.Flag("safebrowsing-disable-auto-update", true),
		)
		allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
		
		// Khởi động browser bằng một root context và duy trì nó
		// Chuyển hướng log của chromedp sang zerolog và ẩn cảnh báo rác
		ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(s string, args ...interface{}) {
			if strings.Contains(s, "unhandled node event") {
				return
			}
			log.Warn().Msgf("chromedp: "+s, args...)
		}))
		
		if err := chromedp.Run(ctx); err != nil {
			cancel()
			allocCancel()
			return nil, fmt.Errorf("failed to launch headless chrome: %w", err)
		}

		browserAllocCtx = allocCtx
		browserAllocCancel = allocCancel
		rootBrowserCtx = ctx
		rootBrowserCancel = cancel
	}
	return rootBrowserCtx, nil
}

// ShutdownBrowserAllocator shuts down the global headless chrome instance safely
func ShutdownBrowserAllocator() {
	browserMu.Lock()
	defer browserMu.Unlock()
	if rootBrowserCancel != nil {
		rootBrowserCancel()
		rootBrowserCtx = nil
		rootBrowserCancel = nil
	}
	if browserAllocCancel != nil {
		browserAllocCancel()
		browserAllocCtx = nil
		browserAllocCancel = nil
	}
}

// RunSpeedTest executes a full headless browser test
func RunSpeedTest(ctx context.Context, targetURL string) (*models.SpeedTestResult, error) {
	rootCtx, err := getRootBrowserContext()
	if err != nil {
		return nil, err
	}

	taskCtx, cancel := chromedp.NewContext(rootCtx)
	defer cancel()

	// Timeout for the entire test
	taskCtx, cancel = context.WithTimeout(taskCtx, 30*time.Second)
	defer cancel()

	var (
		reqs       = make(map[network.RequestID]*models.NetworkRequest)
		hostCache  = make(map[string]bool)
		res        models.SpeedTestResult
		pageStart  float64
		mu         sync.Mutex // Protect reqs, pageStart, and hostCache
	)

	res.TargetURL = targetURL

	// Listen to network events to build waterfall and stats
	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventRequestWillBeSent:
			mu.Lock()
			if pageStart == 0 {
				pageStart = e.Timestamp.Time().Sub(time.Unix(0, 0)).Seconds() * 1000 // approx ms
			}
			reqs[e.RequestID] = &models.NetworkRequest{
				URL:        e.Request.URL,
				Method:     e.Request.Method,
				ResourceType: string(e.Type),
				StartTime:  e.Timestamp.Time().Sub(time.Unix(0, 0)).Seconds() * 1000 - pageStart,
				ReqHeaders: formatHeaders(e.Request.Headers),
			}
			mu.Unlock()
		case *network.EventResponseReceived:
			mu.Lock()
			if r, ok := reqs[e.RequestID]; ok {
				r.StatusCode = int(e.Response.Status)
				r.MimeType = e.Response.MimeType
				r.RespHeaders = formatHeaders(e.Response.Headers)
				r.Size = int64(e.Response.EncodedDataLength)
				if r.Size == 0 && e.Response.Headers != nil {
					// Some fallback if headers have content-length
					if cl, ok := e.Response.Headers["Content-Length"]; ok {
						_ = cl
					}
				}
				
				// Parse Timing
				if t := e.Response.Timing; t != nil {
					r.Timeline.DNS = t.DNSEnd - t.DNSStart
					if r.Timeline.DNS < 0 { r.Timeline.DNS = 0 }
					r.Timeline.Connect = t.ConnectEnd - t.ConnectStart
					if r.Timeline.Connect < 0 { r.Timeline.Connect = 0 }
					r.Timeline.SSL = t.SslEnd - t.SslStart
					if r.Timeline.SSL < 0 { r.Timeline.SSL = 0 }
					r.Timeline.Send = t.SendEnd - t.SendStart
					if r.Timeline.Send < 0 { r.Timeline.Send = 0 }
					r.Timeline.Wait = t.ReceiveHeadersEnd - t.SendEnd
					if r.Timeline.Wait < 0 { r.Timeline.Wait = 0 }

					first := t.DNSStart
					if first < 0 { first = t.ConnectStart }
					if first < 0 { first = t.SendStart }
					if first > 0 { r.Timeline.Blocked = first }
				}
			}
			mu.Unlock()
		case *network.EventLoadingFinished:
			mu.Lock()
			if r, ok := reqs[e.RequestID]; ok {
				r.Size = int64(e.EncodedDataLength)
				r.EndTime = e.Timestamp.Time().Sub(time.Unix(0, 0)).Seconds() * 1000 - pageStart
				r.Duration = r.EndTime - r.StartTime
				r.Timeline.Receive = r.Duration - (r.Timeline.Blocked + r.Timeline.DNS + r.Timeline.Connect + r.Timeline.SSL + r.Timeline.Send + r.Timeline.Wait)
				if r.Timeline.Receive < 0 { r.Timeline.Receive = 0 }
			}
			mu.Unlock()
		case *network.EventLoadingFailed:
			mu.Lock()
			if r, ok := reqs[e.RequestID]; ok {
				r.Error = e.ErrorText
				r.EndTime = e.Timestamp.Time().Sub(time.Unix(0, 0)).Seconds() * 1000 - pageStart
				r.Duration = r.EndTime - r.StartTime
			}
			mu.Unlock()
		case *fetch.EventRequestPaused:
			go func(reqID fetch.RequestID, reqURL string) {
				u, err := url.Parse(reqURL)
				if err != nil {
					_ = chromedp.Run(taskCtx, fetch.FailRequest(reqID, network.ErrorReasonAccessDenied))
					return
				}
				if u.Scheme == "data" || u.Scheme == "blob" {
					_ = chromedp.Run(taskCtx, fetch.ContinueRequest(reqID))
					return
				}
				if u.Scheme != "http" && u.Scheme != "https" {
					_ = chromedp.Run(taskCtx, fetch.FailRequest(reqID, network.ErrorReasonAccessDenied))
					return
				}
				host := u.Hostname()
				if host == "" {
					_ = chromedp.Run(taskCtx, fetch.FailRequest(reqID, network.ErrorReasonAccessDenied))
					return
				}

				mu.Lock()
				safe, exists := hostCache[host]
				mu.Unlock()

				if !exists {
					ctx, cancel := context.WithTimeout(taskCtx, 2*time.Second)
					safe = validator.IsSafeHostnameWithContext(ctx, host)
					cancel()
					mu.Lock()
					hostCache[host] = safe
					mu.Unlock()
				}

				if !safe {
					_ = chromedp.Run(taskCtx, fetch.FailRequest(reqID, network.ErrorReasonAccessDenied))
				} else {
					_ = chromedp.Run(taskCtx, fetch.ContinueRequest(reqID))
				}
			}(e.RequestID, e.Request.URL)
		}
	})

	var actualURL string
	
	// Start navigation
	err = chromedp.Run(taskCtx,
		network.Enable(),
		fetch.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.Evaluate(`window.location.href`, &actualURL),
		chromedp.WaitReady(`body`, chromedp.ByQuery),
	)
	if err != nil {
		return nil, err
	}
	
	res.FinalURL = actualURL

	// Process data
	var totalSize int64
	var maxEndTime float64
	res.ResponseCodes = make(map[string]int)

	contentMap := make(map[string]*models.ContentStat)
	domainMap := make(map[string]*models.DomainStat)

	mu.Lock()
	for _, r := range reqs {
		// Only track http/https
		if !strings.HasPrefix(r.URL, "http") {
			continue
		}
		// Tạo bản copy tránh data race sau này
		reqCopy := *r
		res.Requests = append(res.Requests, reqCopy)
		totalSize += r.Size
		if r.EndTime > maxEndTime {
			maxEndTime = r.EndTime
		}

		// Group Response Codes
		if r.StatusCode > 0 {
			res.ResponseCodes[string(rune(r.StatusCode/100 + '0'))+"xx"]++ // simple grouping or exact
		}

		// Content Type Grouping
		ctype := simplifyResourceType(r.ResourceType)
		if _, ok := contentMap[ctype]; !ok {
			contentMap[ctype] = &models.ContentStat{Type: ctype}
		}
		contentMap[ctype].Size += r.Size
		contentMap[ctype].Requests++

		// Domain Grouping
		if u, err := url.Parse(r.URL); err == nil {
			host := u.Hostname()
			if _, ok := domainMap[host]; !ok {
				domainMap[host] = &models.DomainStat{Domain: host}
			}
			domainMap[host].Size += r.Size
			domainMap[host].Requests++
		}
	}
	mu.Unlock()

	for _, c := range contentMap { res.ContentStats = append(res.ContentStats, *c) }
	for _, d := range domainMap { res.DomainStats = append(res.DomainStats, *d) }

	res.TotalRequests = len(res.Requests)
	res.PageSizeBytes = totalSize
	res.LoadTimeMs = maxEndTime

	// Sort requests by StartTime to make ordering deterministic
	sort.Slice(res.Requests, func(i, j int) bool {
		return res.Requests[i].StartTime < res.Requests[j].StartTime
	})

	calculatePerformanceGrades(&res)

	return &res, nil
}

func calculatePerformanceGrades(res *models.SpeedTestResult) {
	reqs := res.TotalRequests
	reqScore := 100 - (reqs-50)*2
	if reqScore > 100 { reqScore = 100 }
	if reqScore < 0 { reqScore = 0 }

	cookieViolations := 0
	staticReqs := 0
	gzipViolations := 0
	redirects := 0
	emptySrcViolations := 0
	dnsResolutions := make(map[string]bool)

	for _, req := range res.Requests {
		simType := req.ResourceType
		if simType == "Stylesheet" || strings.Contains(req.MimeType, "text/css") {
			simType = "CSS"
		} else if strings.Contains(req.MimeType, "javascript") {
			simType = "Script"
		} else if strings.HasPrefix(req.MimeType, "image/") {
			simType = "Image"
		} else if strings.Contains(req.MimeType, "font") {
			simType = "Font"
		}

		if simType == "Image" || simType == "CSS" || simType == "Script" || simType == "Font" {
			staticReqs++
			// check cookies in Request Headers
			hasCookie := false
			for k := range req.ReqHeaders {
				if strings.ToLower(k) == "cookie" {
					hasCookie = true
					break
				}
			}
			if hasCookie {
				cookieViolations++
			}
			
			// check gzip for text
			if simType == "CSS" || simType == "Script" {
				ce := ""
				for k, v := range req.RespHeaders {
					if strings.ToLower(k) == "content-encoding" {
						ce = strings.ToLower(fmt.Sprintf("%v", v))
						break
					}
				}
				if !strings.Contains(ce, "gzip") && !strings.Contains(ce, "br") {
					gzipViolations++
				}
			}
		}
		if req.StatusCode >= 300 && req.StatusCode < 400 {
			redirects++
		}
		
		if req.URL != "" && !strings.HasPrefix(req.URL, "data:") {
			u, err := url.Parse(req.URL)
			if err == nil && u.Host != "" {
				dnsResolutions[u.Host] = true
			}
		}

		// Empty src check: if a request fetches the exact final URL but isn't Document
		if req.URL == res.FinalURL && simType != "Document" {
			emptySrcViolations++
		}
	}

	cookieScore := 100
	if staticReqs > 0 {
		cookieScore = 100 - (cookieViolations * 100 / staticReqs)
	}

	gzipScore := 100
	if staticReqs > 0 {
		gzipScore = 100 - (gzipViolations * 5)
		if gzipScore < 0 { gzipScore = 0 }
	}

	redirectScore := 100 - (redirects * 10)
	if redirectScore < 0 { redirectScore = 0 }

	dnsScore := 100 - (len(dnsResolutions) * 5)
	if dnsScore < 0 { dnsScore = 0 }
	if dnsScore > 100 { dnsScore = 100 }

	emptySrcScore := 100 - (emptySrcViolations * 20)
	if emptySrcScore < 0 { emptySrcScore = 0 }

	// Calculate Cache/Expires score based on headers presence in static assets
	expiresViolations := 0
	for _, req := range res.Requests {
		simType := req.ResourceType
		if simType == "Stylesheet" || strings.Contains(req.MimeType, "text/css") {
			simType = "CSS"
		} else if strings.Contains(req.MimeType, "javascript") {
			simType = "Script"
		} else if strings.HasPrefix(req.MimeType, "image/") {
			simType = "Image"
		} else if strings.Contains(req.MimeType, "font") {
			simType = "Font"
		}

		if simType == "Image" || simType == "CSS" || simType == "Script" || simType == "Font" {
			hasCache := false
			for k, v := range req.RespHeaders {
				lk := strings.ToLower(k)
				lv := strings.ToLower(fmt.Sprintf("%v", v))
				if lk == "cache-control" {
					if strings.Contains(lv, "no-store") || strings.Contains(lv, "no-cache") || strings.Contains(lv, "private") || strings.Contains(lv, "max-age=0") {
						hasCache = false
					} else if strings.Contains(lv, "max-age") || strings.Contains(lv, "public") || strings.Contains(lv, "immutable") {
						hasCache = true
					}
					break
				}
				if lk == "expires" && lv != "0" && lv != "-1" && !hasCache {
					hasCache = true
					// Don't break here just in case there's a cache-control that overrides it
				}
			}
			if !hasCache {
				expiresViolations++
			}
		}
	}
	
	expiresScore := 100
	if staticReqs > 0 {
		expiresScore = 100 - (expiresViolations * 100 / staticReqs)
	}

	grades := []models.PerformanceGrade{
		{Rule: "Giảm thiểu số lượng HTTP Request", Score: reqScore, Grade: getLetter(reqScore), Description: "Cắt giảm số lượng thành phần trên trang sẽ giúp giảm thiểu số lượng HTTP Request cần thiết để tải trang."},
		{Rule: "Sử dụng tên miền Cookie-free", Score: cookieScore, Grade: getLetter(cookieScore), Description: "Tài nguyên tĩnh nên được tải thông qua các truy vấn không chứa cookie."},
		{Rule: "Bổ sung HTTP Header Cache/Expires", Score: expiresScore, Grade: getLetter(expiresScore), Description: "Bổ sung HTTP Header Cache-Control/Expires biến tài nguyên tĩnh thành dữ liệu lưu bộ nhớ đệm."},
		{Rule: "Nén tài nguyên bằng Gzip/Brotli", Score: gzipScore, Grade: getLetter(gzipScore), Description: "Nén dữ liệu giúp rút ngắn thời gian phản hồi bằng cách thu nhỏ kích thước HTTP."},
		{Rule: "Tối ưu số lần phân giải DNS", Score: dnsScore, Grade: getLetter(dnsScore), Description: "Mỗi host lạ cần thời gian tra cứu DNS. Giảm thiểu các host bên ngoài giúp tăng tốc tải trang."},
		{Rule: "Hạn chế chuyển hướng URL (Redirect)", Score: redirectScore, Grade: getLetter(redirectScore), Description: "Chuyển hướng chèn thêm một bước trung gian làm chậm toàn bộ quá trình tải."},
		{Rule: "Tránh để trống thuộc tính src/href", Score: emptySrcScore, Grade: getLetter(emptySrcScore), Description: "Tránh lỗi vòng lặp hoặc request trống làm lãng phí tài nguyên trình duyệt."},
	}

	totalScore := (reqScore + cookieScore + expiresScore + gzipScore + dnsScore + redirectScore + emptySrcScore) / 7
	res.PerformanceGrade = totalScore
	res.PerformanceLetter = getLetter(totalScore)
	res.Grades = grades
}

func getLetter(score int) string {
	if score >= 90 { return "A" }
	if score >= 80 { return "B" }
	if score >= 70 { return "C" }
	if score >= 60 { return "D" }
	return "F"
}

func formatHeaders(h network.Headers) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		m[k] = fmt.Sprintf("%v", v)
	}
	return m
}

func simplifyResourceType(rt string) string {
	switch rt {
	case "Image": return "Image"
	case "Script": return "Script"
	case "Stylesheet": return "CSS"
	case "Document": return "HTML"
	case "Font": return "Font"
	default: return "Other"
	}
}
