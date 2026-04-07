package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/web-latency/models"
)

func AnalyzeLatency(ctx context.Context, rawURL string, deepTest bool) (*models.WebLatencyResult, error) {
	// 1. Chuẩn hoá URL
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL // Ưu tiên HTTPS
	}

	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, errors.New("địa chỉ URL không hợp lệ")
	}

	result := &models.WebLatencyResult{
		TargetURL: parsedURL.String(),
		IsUp:      false,
	}

	hops := []models.Hop{}
	var finalMetrics models.TimingMetrics
	var finalResp *http.Response

	currentURL := parsedURL.String()
	maxRedirects := 5

	for i := 0; i < maxRedirects; i++ {
		hopResult, resp, err := measureSingleHop(ctx, currentURL)
		if err != nil {
			return nil, fmt.Errorf("lỗi kết nối tại hop %d: %v", i+1, err)
		}

		hop := models.Hop{
			URL:        currentURL,
			StatusCode: resp.StatusCode,
			Metrics:    *hopResult,
			Total:      hopResult.Total,
		}
		hops = append(hops, hop)
		
		finalMetrics = *hopResult
		finalResp = resp
		result.IsUp = true
		result.FinalURL = currentURL

		// Check if redirect
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			location := resp.Header.Get("Location")
			if location == "" {
				break
			}
			
			locURL, err := resp.Location()
			if err != nil {
				break
			}
			currentURL = locURL.String()
			
			// Close previous body to reuse connection
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		} else {
			break
		}
	}

	// Nếu loop xong mà status code vẫn là redirect thì báo lỗi quá limit
	if finalResp != nil && finalResp.StatusCode >= 300 && finalResp.StatusCode <= 399 {
		finalResp.Body.Close()
		return nil, errors.New("vượt quá giới hạn chuyển hướng (tối đa 5 hops)")
	}

	result.RedirectHops = hops
	result.PrimaryMetrics = finalMetrics

	// Parse Compression Info on final response
	if finalResp != nil {
		result.Compression = parseCompression(finalResp)
		io.Copy(io.Discard, finalResp.Body) // Ensure read to end before close
		finalResp.Body.Close()
	}

	// 2. Nếu Deep Test (3 vòng lặp) trên URL cuối cùng
	if deepTest && result.IsUp {
		ttfbList := []time.Duration{finalMetrics.TTFB}

		for r := 0; r < 2; r++ {
			// Delay 1.5s as requested by user
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}

			hopMetrics, resp, err := measureSingleHop(ctx, currentURL)
			if err == nil && resp != nil {
				ttfbList = append(ttfbList, hopMetrics.TTFB)
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		sort.Slice(ttfbList, func(i, j int) bool { return ttfbList[i] < ttfbList[j] })
		minTTFB := ttfbList[0]
		maxTTFB := ttfbList[len(ttfbList)-1]
		var medianTTFB time.Duration
		if len(ttfbList) == 3 {
			medianTTFB = ttfbList[1]
		} else if len(ttfbList) == 2 {
			medianTTFB = (ttfbList[0] + ttfbList[1]) / 2
		} else {
			medianTTFB = ttfbList[0]
		}

		result.DeepTestResults = &models.DeepTestInfo{
			MinTTFB:    minTTFB,
			MedianTTFB: medianTTFB,
			MaxTTFB:    maxTTFB,
			Rounds:     len(ttfbList),
		}
	}

	return result, nil
}

func measureSingleHop(ctx context.Context, targetURL string) (*models.TimingMetrics, *http.Response, error) {
	var (
		dnsStart, dnsDone   time.Time
		tcpStart, tcpDone   time.Time
		tlsStart, tlsDone   time.Time
		requestWritten      time.Time
		firstByte           time.Time
		doneTime            time.Time
	)

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, nil, err
	}
	
	// Set user agent
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 bctechvibe-bot/1.0")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

	trace := &httptrace.ClientTrace{
		DNSStart:          func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone:           func(_ httptrace.DNSDoneInfo) { dnsDone = time.Now() },
		ConnectStart:      func(_, _ string) { tcpStart = time.Now() },
		ConnectDone:       func(_, _ string, _ error) { tcpDone = time.Now() },
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { tlsDone = time.Now() },
		WroteRequest:      func(_ httptrace.WroteRequestInfo) { requestWritten = time.Now() },
		GotFirstResponseByte: func() { firstByte = time.Now() },
	}

	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))

	// Tránh auto follow redirect
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	totalStart := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	// Đọc body để tính ContentDownload time
	// Giới hạn đọc tối đa 5MB để không tốn băng thông/RAM server
	const maxReadSize = 5 * 1024 * 1024
	io.CopyN(io.Discard, resp.Body, maxReadSize)
	doneTime = time.Now()

	metrics := &models.TimingMetrics{}
	
	if !dnsStart.IsZero() && !dnsDone.IsZero() {
		metrics.DNSLookup = dnsDone.Sub(dnsStart)
	}
	// Do HTTP Keep-Alive, TCP connection start/done check:
	if !tcpStart.IsZero() && !tcpDone.IsZero() {
		metrics.TCPConnect = tcpDone.Sub(tcpStart)
	}
	if !tlsStart.IsZero() && !tlsDone.IsZero() {
		metrics.TLSHandshake = tlsDone.Sub(tlsStart)
	}
	if !requestWritten.IsZero() && !firstByte.IsZero() {
		metrics.TTFB = firstByte.Sub(requestWritten)
	}
	if !firstByte.IsZero() {
		metrics.ContentDownload = doneTime.Sub(firstByte)
	}	
	metrics.Total = doneTime.Sub(totalStart)

	return metrics, resp, nil
}

func parseCompression(resp *http.Response) models.CompressionInfo {
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	return models.CompressionInfo{
		Encoding:     enc,
		IsCompressed: enc == "gzip" || enc == "br" || enc == "zstd" || enc == "deflate",
		ContentType:  resp.Header.Get("Content-Type"),
		CacheControl: resp.Header.Get("Cache-Control"),
		ETag:         resp.Header.Get("ETag"),
		XCache:       resp.Header.Get("X-Cache"),
		Server: 	  resp.Header.Get("Server"),
		HTTPVersion:  resp.Proto,
	}
}
