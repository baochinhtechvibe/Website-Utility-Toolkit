package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/platform/validator"
)

const (
	// Thời gian tối đa chờ một request đơn
	RequestTimeout = 15 * time.Second
	// Số redirect tối đa theo sau
	MaxRedirects = 10
	// Kích thước body tối đa đọc về (1MB)
	MaxBodyBytes = 1 * 1024 * 1024
	// Kích thước snippet hiển thị (4KB)
	MaxSnippetBytes = 4 * 1024
	// Timeout cho mỗi dial TCP
	DialTimeout = 5 * time.Second
)

// HTTPResult chứa kết quả raw của một request HTTP.
type HTTPResult struct {
	FinalURL        string
	StatusCode      int
	StatusText      string
	ContentType     string
	PayloadBytes    int64
	Headers         map[string]string
	Body            string // full body tối đa MaxBodyBytes
	BodySnippet     string // snippet giới hạn MaxSnippetBytes
	RedirectChain   []HopSummary
	Error           string
}

// HopSummary mô tả một bước redirect gọn nhẹ.
type HopSummary struct {
	Step       int
	URL        string
	StatusCode int
	StatusText string
}

// FetchOptions cho phép tuỳ chỉnh request.
type FetchOptions struct {
	UserAgent       string
	ExtraHeaders    map[string]string
	IgnoreTLSErrors bool
	FollowRedirects bool // nếu false sẽ dừng ở redirect đầu tiên
}

// buildClient tạo HTTP client với timeout, SSRF protection và giới hạn redirect.
func buildClient(opts FetchOptions) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: opts.IgnoreTLSErrors}, //nolint:gosec
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.LookupIP(host)
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
				return nil, fmt.Errorf("SSRF Protection: không tìm thấy IP an toàn cho %s", host)
			}
			return (&net.Dialer{
				Timeout:   DialTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
	}

	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if !opts.FollowRedirects {
			return http.ErrUseLastResponse
		}
		if len(via) >= MaxRedirects {
			return fmt.Errorf("đã vượt quá số lượng redirect tối đa (%d)", MaxRedirects)
		}
		return nil
	}

	return &http.Client{
		Transport:     transport,
		CheckRedirect: checkRedirect,
		Timeout:       RequestTimeout,
	}
}

// buildRequest tạo HTTP request kèm header sanitization và SSRF check.
func buildRequest(rawURL string, opts FetchOptions) (*http.Request, error) {

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL không hợp lệ: %w", err)
	}

	req, err := http.NewRequest("GET", parsedURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo request: %w", err)
	}

	// Sanitize và set User-Agent
	ua := sanitizeHeaderValue(opts.UserAgent)
	if ua == "" {
		ua = "BotSimulator/1.0"
	}
	req.Header.Set("User-Agent", ua)

	// Set extra headers từ profile
	for k, v := range opts.ExtraHeaders {
		kSafe := sanitizeHeaderValue(k)
		vSafe := sanitizeHeaderValue(v)
		if kSafe != "" && vSafe != "" {
			req.Header.Set(kSafe, vSafe)
		}
	}

	// Mặc định Accept nếu chưa set
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	return req, nil
}

// sanitizeHeaderValue loại bỏ ký tự CR/LF để ngăn header injection.
func sanitizeHeaderValue(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, s)
}

// FetchPage thực hiện request HTTP hoàn chỉnh với capture redirect chain.
// Dùng custom DialContext để SSRF check mọi hop.
func FetchPage(rawURL string, opts FetchOptions) (*HTTPResult, error) {
	result := &HTTPResult{}
	chain := []HopSummary{}

	currentURL := rawURL
	if !strings.HasPrefix(currentURL, "http://") && !strings.HasPrefix(currentURL, "https://") {
		currentURL = "https://" + currentURL
	}

	// Client không tự theo redirect — tao tự quản lý để capture chain
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: opts.IgnoreTLSErrors}, //nolint:gosec
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.LookupIP(host)
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
					return nil, fmt.Errorf("SSRF Protection: không tìm thấy IP an toàn cho %s", host)
				}
				return (&net.Dialer{
					Timeout:   DialTimeout,
					KeepAlive: 30 * time.Second,
				}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: RequestTimeout,
	}

	for step := 1; step <= MaxRedirects+1; step++ {
		req, err := buildRequest(currentURL, opts)
		if err != nil {
			result.Error = err.Error()
			break
		}

		resp, err := client.Do(req)
		if err != nil {
			if len(chain) == 0 {
				result.Error = err.Error()
				result.FinalURL = currentURL
			}
			break
		}

		chain = append(chain, HopSummary{
			Step:       step,
			URL:        currentURL,
			StatusCode: resp.StatusCode,
			StatusText: http.StatusText(resp.StatusCode),
		})

		isRedirectCode := resp.StatusCode >= 300 && resp.StatusCode < 400
		if !isRedirectCode || !opts.FollowRedirects {
			// Đây là response cuối
			result.StatusCode = resp.StatusCode
			result.StatusText = http.StatusText(resp.StatusCode)
			result.FinalURL = currentURL
			result.ContentType = resp.Header.Get("Content-Type")

			// Lọc headers trả về client (bỏ header nhạy cảm)
			result.Headers = filteredHeaders(resp.Header)

			// Đọc body với giới hạn
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
			resp.Body.Close()
			result.PayloadBytes = int64(len(bodyBytes))

			if strings.Contains(strings.ToLower(result.ContentType), "text/html") ||
				strings.Contains(strings.ToLower(result.ContentType), "text/plain") {
				result.Body = string(bodyBytes)
				if len(bodyBytes) > MaxSnippetBytes {
					result.BodySnippet = string(bodyBytes[:MaxSnippetBytes])
				} else {
					result.BodySnippet = result.Body
				}
			}
			break
		}

		// Theo redirect
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if loc == "" {
			result.Error = "redirect không có Location header"
			break
		}
		parsedBase, _ := url.Parse(currentURL)
		parsedLoc, err := url.Parse(loc)
		if err != nil || parsedBase == nil {
			result.Error = "Location header không hợp lệ"
			break
		}
		currentURL = parsedBase.ResolveReference(parsedLoc).String()

		if step == MaxRedirects+1 {
			result.Error = fmt.Sprintf("vượt quá số lượng redirect tối đa (%d)", MaxRedirects)
		}
	}

	result.RedirectChain = chain
	if result.FinalURL == "" {
		result.FinalURL = currentURL
	}

	return result, nil
}

// filteredHeaders loại bỏ header nhạy cảm trước khi trả về client.
func filteredHeaders(h http.Header) map[string]string {
	sensitive := map[string]bool{
		"x-powered-by":     true,
		"x-aspnet-version": true,
	}
	out := make(map[string]string, len(h))
	for k, vv := range h {
		kl := strings.ToLower(k)
		if sensitive[kl] || strings.HasPrefix(kl, "x-internal-") {
			continue
		}
		out[k] = strings.Join(vv, ", ")
	}
	return out
}

// FetchRaw thực hiện request đơn (không theo redirect) trả về full response.
// Dùng để fetch robots.txt với đầy đủ xử lý status code theo RFC 9309.
func FetchRaw(rawURL string, ua string, ignoreTLS bool) (*http.Response, []byte, error) {
	opts := FetchOptions{
		UserAgent:       ua,
		IgnoreTLSErrors: ignoreTLS,
		FollowRedirects: false,
	}
	client := buildClient(opts)

	req, err := buildRequest(rawURL, opts)
	if err != nil {
		return nil, nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	return resp, body, nil
}

// NormalizeURL thêm scheme nếu URL thiếu.
func NormalizeURL(rawURL string) (string, error) {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL không hợp lệ: %w", err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL thiếu hostname")
	}
	return u.String(), nil
}

// RobotsURL xây dựng URL đến file robots.txt của domain.
func RobotsURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s://%s/robots.txt", u.Scheme, u.Host), nil
}

// SameDomain kiểm tra 2 URL có cùng host không.
func SameDomain(a, b string) bool {
	ua, err1 := url.Parse(a)
	ub, err2 := url.Parse(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}

// TimeoutError kiểm tra xem error có phải do timeout không.
func TimeoutError(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}

// HashBody tạo hash ngắn (8 ký tự) cho body phục vụ compare.
func HashBody(body string) string {
	if body == "" {
		return ""
	}
	// Simple djb2 hash cho mục đích so sánh nội dung
	h := uint32(5381)
	for _, c := range []byte(body) {
		h = (h << 5) + h + uint32(c)
	}
	return fmt.Sprintf("%08x", h)
}

// safeTime tránh panic khi chia cho 0.
func safeTime(d time.Duration) int64 {
	return d.Milliseconds()
}
