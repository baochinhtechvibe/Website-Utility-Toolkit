package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
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
	// Kích thước body tối đa đọc về (10MB - Rule #57)
	MaxBodyBytes = 10 * 1024 * 1024
	// Kích thước snippet hiển thị (4KB)
	MaxSnippetBytes = 4 * 1024
	// Timeout cho mỗi dial TCP
	DialTimeout = 5 * time.Second
)

var (
	// Singleton clients (Rule #55)
	defaultClient  *http.Client
	insecureClient *http.Client
)

func init() {
	// Transport dùng chung với pooling (Rule #53)
	baseTransport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       SafeDialContext,
		ForceAttemptHTTP2: true,
		MaxIdleConns:      100,
		IdleConnTimeout:   90 * time.Second,
		// Tắt Keep-Alive nếu cần cực kỳ khắt khe, nhưng ở đây ta bật để tối ưu pooling
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Client chuẩn (Không follow redirect tự động)
	defaultClient = &http.Client{
		Transport: baseTransport,
		Timeout:   RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Client bỏ qua lỗi TLS
	insecureTransport := baseTransport.Clone()
	insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	insecureClient = &http.Client{
		Transport: insecureTransport,
		Timeout:   RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

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

// getClient trả về singleton client phù hợp.
func getClient(ignoreTLS bool) *http.Client {
	if ignoreTLS {
		return insecureClient
	}
	return defaultClient
}

// buildRequest tạo HTTP request kèm header sanitization.
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
func FetchPage(ctx context.Context, rawURL string, opts FetchOptions) (*HTTPResult, error) {
	result := &HTTPResult{}
	chain := []HopSummary{}

	currentURL := rawURL
	if !strings.HasPrefix(currentURL, "http://") && !strings.HasPrefix(currentURL, "https://") {
		currentURL = "https://" + currentURL
	}

	client := getClient(opts.IgnoreTLSErrors)

	for step := 1; step <= MaxRedirects+1; step++ {
		req, err := buildRequest(currentURL, opts)
		if err != nil {
			result.Error = err.Error()
			break
		}
		req = req.WithContext(ctx)

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

			// Lọc headers trả về client
			result.Headers = filteredHeaders(resp.Header)

			// Đọc body với giới hạn (Rule #57)
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
			resp.Body.Close()
			result.PayloadBytes = int64(len(bodyBytes))

			ct := strings.ToLower(result.ContentType)
			if strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") || strings.Contains(ct, "xml") {
				result.Body = string(bodyBytes)
				// Cắt snippet an toàn theo rune để không cắt ngang ký tự đa byte (Rule #50)
				if len(bodyBytes) > MaxSnippetBytes {
					result.BodySnippet = truncateRuneSafe(result.Body, MaxSnippetBytes)
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

// FetchRaw thực hiện request đơn (không theo redirect) trả về status code và body.
// Design này tránh lỗi Double Close body (Rule #Gemini - Review fix).
func FetchRaw(ctx context.Context, rawURL string, ua string, ignoreTLS bool) (int, []byte, error) {
	opts := FetchOptions{
		UserAgent:       ua,
		IgnoreTLSErrors: ignoreTLS,
		FollowRedirects: false,
	}
	client := getClient(ignoreTLS)

	req, err := buildRequest(rawURL, opts)
	if err != nil {
		return 0, nil, err
	}
	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	return resp.StatusCode, body, nil
}

// NormalizeURL thêm scheme nếu URL thiếu.
func NormalizeURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
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

// truncateRuneSafe cắt chuỗi an toàn theo byte budget mà không cắt ngang ký tự đa byte (Rule #50).
// Nó chuyển sang []rune để đảm bảo không làm hỏng ký tự Tiếng Việt hay Emoji.
func truncateRuneSafe(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	runes := []rune(s)
	result := ""
	for _, r := range runes {
		candidate := result + string(r)
		if len(candidate) > maxBytes {
			break
		}
		result = candidate
	}
	return result
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
	h := fnv.New32a()
	h.Write([]byte(body))
	return fmt.Sprintf("%08x", h.Sum32())
}

// SafeDialContext là hàm dial tuỳ chỉnh hỗ trợ SSRF protection bằng cách chỉ kết nối tới IP an toàn.
func SafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	// Dùng DefaultResolver kèm context để tránh Goroutine leak (Rule #Review Fix)
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
		return nil, fmt.Errorf("SSRF Protection: không tìm thấy IP an toàn cho %s", host)
	}
	return (&net.Dialer{
		Timeout:   DialTimeout,
		KeepAlive: 30 * time.Second,
	}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
}
