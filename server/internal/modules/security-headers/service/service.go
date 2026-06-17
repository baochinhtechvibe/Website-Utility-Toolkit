// ============================================
// FILE: security-headers/service/service.go
//
// Entry point chính: Analyze(ctx, targetURL)
//   - Follow redirect (Go default, max 10)
//   - Dual timeout: Client + Context
//   - User-Agent giả lập Chrome
//   - Theo dõi redirect chain (HTTP→HTTP warning)
//   - Tổng hợp kết quả từ headers, cookies, leaks
//   - Tính điểm + xếp hạng grade
//   - Xử lý lỗi TLS riêng biệt (không skip verify)
// ============================================

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

var (
	ErrConnectionFailed = errors.New("connection failed")
	ErrTLSFailed        = errors.New("tls verification failed")
	ErrSSRFBlocked      = errors.New("truy cập bị chặn (SSRF protection)")
)

const (
	userAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 SecurityHeaders/1.0 (+https://bctechvibe.com)"
	clientTimeout = 10 * time.Second
)

// ===========================
// MAIN ENTRY POINT
// ===========================

var (
	safeClient       *http.Client
	noRedirectClient *http.Client
)

func init() {
	safeClient = &http.Client{
		Timeout:   clientTimeout,
		Transport: buildSafeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("quá nhiều redirect (%d lần)", len(via))
			}
			return nil
		},
	}

	noRedirectClient = &http.Client{
		Timeout:   clientTimeout,
		Transport: buildSafeTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func buildSafeTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			var safeIP net.IP
			for _, ipAddr := range ips {
				if validator.IsSafeIP(ipAddr.IP) {
					safeIP = ipAddr.IP
					break
				}
			}
			if safeIP == nil {
				return nil, fmt.Errorf("SSRF Protection: chặn kết nối đến IP nội bộ %s", host)
			}
			return (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// getRedirectChain build the redirect chain from the final response backwards
func getRedirectChain(resp *http.Response) []models.RedirectHop {
	var chain []models.RedirectHop
	
	// Add final response hop
	chain = append(chain, models.RedirectHop{
		URL:        resp.Request.URL.String(),
		StatusCode: resp.StatusCode,
		HasHSTS:    resp.Header.Get("Strict-Transport-Security") != "",
	})

	curr := resp
	for curr != nil && curr.Request != nil && curr.Request.Response != nil {
		curr = curr.Request.Response
		chain = append(chain, models.RedirectHop{
			URL:        curr.Request.URL.String(),
			StatusCode: curr.StatusCode,
			HasHSTS:    curr.Header.Get("Strict-Transport-Security") != "",
		})
	}
	
	// Reverse the chain to make it chronological (Hop 1 -> Hop 2 -> Final)
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	
	return chain
}

// Analyze nhận URL đầy đủ (đã normalize), gửi request, phân tích header
func Analyze(ctx context.Context, targetURL string, followRedirects bool) (*models.AnalyzeResponse, error) {

	// 1. Dùng client phù hợp
	var client *http.Client
	if followRedirects {
		client = safeClient
	} else {
		client = noRedirectClient
	}

	// 2. Build request với User-Agent
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// 3. Execute request
	resp, err := client.Do(req)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "SSRF Protection") {
			return nil, ErrSSRFBlocked
		}
		if strings.Contains(errMsg, "tls:") || strings.Contains(errMsg, "x509:") || strings.Contains(errMsg, "certificate") {
			return nil, fmt.Errorf("%w: %v", ErrTLSFailed, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	// Bug #2 FIX: Drain body trước khi close để tránh connection pool exhaustion
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // Giới hạn 1MB
		resp.Body.Close()
	}()

	// 4. Lấy final URL và đếm redirect
	finalURL := resp.Request.URL.String()
	finalScheme := resp.Request.URL.Scheme
	redirectChain := getRedirectChain(resp)
	redirectCount := len(redirectChain) - 1
	if redirectCount < 0 {
		redirectCount = 0
	}

	// Nếu không follow redirect và response là redirect, grade là R
	isRedirect := !followRedirects && (resp.StatusCode >= 300 && resp.StatusCode <= 399)

	// 5. Detect insecure SSL (nếu scheme cuối vẫn là http, hoặc có hop là http trong chuỗi chuyển hướng)
	hasInsecureSSL := strings.HasPrefix(targetURL, "https://") && finalScheme == "http"
	if len(redirectChain) > 1 {
		for i := 1; i < len(redirectChain); i++ {
			if strings.HasPrefix(redirectChain[i-1].URL, "https://") && strings.HasPrefix(redirectChain[i].URL, "http://") {
				hasInsecureSSL = true
				break
			}
		}
	}

	// 6. Phân tích CORS qua request riêng (Active Probing) tới finalURL
	// Do cần finalURL, CORS probe được chạy sau request chính. Chấp nhận tăng thêm 1 RTT.
	corsChan := make(chan internalCORSAnalysis, 1)
	go func() {
		corsChan <- analyzeCORS(ctx, finalURL)
	}()

	// 7. Phân tích headers
	headerResult := analyzeHeaders(resp, finalScheme)

	// 8. Phân tích cookies
	cookieResult := analyzeCookies(resp, finalScheme)

	// 9. Phân tích information leaks
	leakResult := analyzeLeaks(resp)

	// Chờ CORS probing hoàn thành
	corsResult := <-corsChan

	// 10. Tổng hợp điểm
	score := 100
	score -= headerResult.Penalty
	score -= cookieResult.Penalty
	score -= leakResult.Penalty
	score -= corsResult.Penalty // Trừ điểm CORS

	if score < 0 {
		score = 0
	}

	// 10. Xếp hạng grade
	grade := calculateGrade(score)
	if isRedirect {
		grade = "R"
		score = 0
	}

	// 11. Build config
	config := models.ServerConfig{
		Nginx:  headerResult.NginxConfig,
		Apache: headerResult.ApacheConfig,
	}

	// 8. Additional informational headers
	additionalInfo := analyzeAdditionalHeaders(resp)

	// 9. Raw headers — extract tất cả, sort alphabetical
	rawHeaders := make([]models.RawHeader, 0, len(resp.Header))
	for name, values := range resp.Header {
		for _, val := range values {
			rawHeaders = append(rawHeaders, models.RawHeader{
				Name:  name,
				Value: val,
			})
		}
	}
	sort.Slice(rawHeaders, func(i, j int) bool {
		return strings.ToLower(rawHeaders[i].Name) < strings.ToLower(rawHeaders[j].Name)
	})

	return &models.AnalyzeResponse{
		ScannedURL:         targetURL,
		FinalURL:           finalURL,
		RedirectCount:      redirectCount,
		RedirectChain:      redirectChain,
		HasInsecureSSL:     hasInsecureSSL,
		Score:              score,
		Grade:              grade,
		Headers:            headerResult.Headers,
		Cookies:            cookieResult.Cookies,
		HasSetCookie:       cookieResult.HasSetCookie,
		InformationLeakage: leakResult.Leaks,
		Config:             config,
		RawHeaders:         rawHeaders,
		AdditionalInfo:     additionalInfo,
		CORSAnalysis:       corsResult.Data,
		DetectedTech:       leakResult.TechStack,
	}, nil
}

// ===========================
// GRADE CALCULATOR
// ===========================

func calculateGrade(score int) string {
	switch {
	case score >= 95:
		return "A+"
	case score >= 85:
		return "A"
	case score >= 75:
		return "B"
	case score >= 65:
		return "C"
	case score >= 50:
		return "D"
	default:
		return "F"
	}
}

// ===========================
// HELPER: kiểm tra CSP yếu
// ===========================

func analyzeCSP(csp string) []models.CSPIssue {
	var issues []models.CSPIssue
	lower := strings.ToLower(csp)
	directives := strings.Split(lower, ";")

	hasObjectSrc := false
	hasBaseUri := false

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) == 0 {
			continue
		}

		name := parts[0]
		if name == "object-src" {
			hasObjectSrc = true
		}
		if name == "base-uri" {
			hasBaseUri = true
		}

		// Analyze values
		if name == "script-src" || name == "script-src-elem" || name == "script-src-attr" || name == "default-src" || name == "object-src" || name == "base-uri" || name == "style-src" {
			hasStrictDynamic := false
			hasNonceOrHash := false
			for _, val := range parts[1:] {
				if val == "'strict-dynamic'" {
					hasStrictDynamic = true
				}
				if strings.HasPrefix(val, "'nonce-") || strings.HasPrefix(val, "'sha256-") || strings.HasPrefix(val, "'sha384-") || strings.HasPrefix(val, "'sha512-") {
					hasNonceOrHash = true
				}
			}

			for _, val := range parts[1:] {
				if val == "'unsafe-inline'" {
					if name == "style-src" {
						issues = append(issues, models.CSPIssue{Directive: name, Severity: "low", Message: "Cho phép CSS inline ('unsafe-inline') có thể mở đường cho CSS injection, dù rủi ro thấp hơn script."})
					} else {
						if hasStrictDynamic && hasNonceOrHash {
							issues = append(issues, models.CSPIssue{Directive: name, Severity: "info", Message: "'unsafe-inline' bị vô hiệu hoá bởi trình duyệt mới do có nonce/hash và 'strict-dynamic'. Đóng vai trò tương thích ngược (CSP1)."})
						} else {
							issues = append(issues, models.CSPIssue{Directive: name, Severity: "high", Message: "Cho phép thực thi mã inline ('unsafe-inline') có nguy cơ XSS cực kỳ cao."})
						}
					}
				}
				if val == "'unsafe-eval'" {
					issues = append(issues, models.CSPIssue{Directive: name, Severity: "high", Message: "Cho phép hàm eval() ('unsafe-eval') giúp kẻ tấn công dễ dàng thực thi chuỗi payload XSS."})
				}
				if val == "*" {
					issues = append(issues, models.CSPIssue{Directive: name, Severity: "high", Message: "Sử dụng wildcard (*) cho phép load tài nguyên từ bất kỳ domain nào, vô hiệu hoá tác dụng bảo vệ của CSP."})
				}
				if strings.HasPrefix(val, "data:") {
					issues = append(issues, models.CSPIssue{Directive: name, Severity: "medium", Message: "Sử dụng data: URI có thể bị attacker lợi dụng để chèn payload mã độc thông qua data base64."})
				}
				if strings.HasPrefix(val, "http:") {
					issues = append(issues, models.CSPIssue{Directive: name, Severity: "medium", Message: "Cho phép load từ http: làm suy yếu HTTPS và tạo điều kiện cho mixed-content."})
				}
				if val == "'strict-dynamic'" {
					if hasNonceOrHash {
						issues = append(issues, models.CSPIssue{Directive: name, Severity: "info", Message: "'strict-dynamic' được cấu hình an toàn với nonce/hash (Best Practice)."})
					} else {
						issues = append(issues, models.CSPIssue{Directive: name, Severity: "medium", Message: "'strict-dynamic' được sử dụng nhưng thiếu nonce hoặc hash an toàn."})
					}
				}
			}
		}
	}

	if !hasObjectSrc {
		issues = append(issues, models.CSPIssue{Directive: "object-src", Severity: "medium", Message: "Thiếu 'object-src'. Nên set 'object-src 'none'' để chặn load Flash/Java/Plugin độc hại."})
	}
	if !hasBaseUri {
		issues = append(issues, models.CSPIssue{Directive: "base-uri", Severity: "medium", Message: "Thiếu 'base-uri'. Nên set 'base-uri 'none'' hoặc 'self' để chặn chèn thẻ <base> làm sai lệch đường dẫn script."})
	}

	return issues
}

func hasSecureFrameAncestors(csp string) bool {
	lower := strings.ToLower(csp)
	directives := strings.Split(lower, ";")

	for _, directive := range directives {
		directive = strings.TrimSpace(directive)
		if directive == "" {
			continue
		}

		parts := strings.Fields(directive)
		if len(parts) == 0 {
			continue
		}

		name := parts[0]
		if name == "frame-ancestors" {
			if len(parts) > 1 {
				for _, val := range parts[1:] {
					if val == "*" {
						return false
					}
				}
				return true
			}
		}
	}

	return false
}
