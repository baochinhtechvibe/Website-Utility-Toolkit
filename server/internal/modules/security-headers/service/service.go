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
	"net/http"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

var (
	ErrConnectionFailed = errors.New("connection failed")
	ErrTLSFailed        = errors.New("tls verification failed")
)

const (
	userAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	clientTimeout = 10 * time.Second
)

// ===========================
// MAIN ENTRY POINT
// ===========================

// Analyze nhận URL đầy đủ (đã normalize), gửi request, phân tích header
func Analyze(ctx context.Context, targetURL string) (*models.AnalyzeResponse, error) {

	// 1. Build HTTP client — follow redirect mặc định (Go tự theo max 10 hop)
	//    redirectCount được capture bởi closure CheckRedirect.
	//    An toàn vì Go HTTP client chạy sequential — không có race condition.
	var redirectCount int

	client := &http.Client{
		Timeout: clientTimeout,
		// Bug #1 FIX: Bỏ InsecureSkipVerify — security scanner PHẢI verify TLS.
		// Nếu cert tự ký → trả lỗi TLS riêng biệt, rõ ràng cho user.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			redirectCount = len(via) // sequential flow, safe without mutex
			if redirectCount >= 10 {
				return fmt.Errorf("quá nhiều redirect (%d lần)", redirectCount)
			}
			return nil
		},
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
		// TLS error detection — dùng string-based cho portable (không phụ thuộc Go version)
		errMsg := err.Error()
		if strings.Contains(errMsg, "tls:") || strings.Contains(errMsg, "x509:") || strings.Contains(errMsg, "certificate") {
			return nil, fmt.Errorf("%w: %v", ErrTLSFailed, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	// Bug #2 FIX: Drain body trước khi close để tránh connection pool exhaustion
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// 4. Lấy final URL (sau redirect)
	finalURL := resp.Request.URL.String()
	finalScheme := resp.Request.URL.Scheme

	// 5. Detect insecure SSL (nếu scheme cuối vẫn là http)
	hasInsecureSSL := strings.HasPrefix(targetURL, "https://") && finalScheme == "http"

	// 6. Phân tích headers
	headerResult := analyzeHeaders(resp, finalScheme)

	// 7. Phân tích cookies
	cookieResult := analyzeCookies(resp, finalScheme)

	// 8. Phân tích information leaks
	leakResult := analyzeLeaks(resp)

	// 9. Tổng hợp điểm
	score := 100
	score -= headerResult.Penalty
	score -= cookieResult.Penalty
	score -= leakResult.Penalty

	if score < 0 {
		score = 0
	}

	// 10. Xếp hạng grade
	grade := calculateGrade(score)

	// 11. Build config
	config := models.ServerConfig{
		Nginx:  headerResult.NginxConfig,
		Apache: headerResult.ApacheConfig,
	}

	return &models.AnalyzeResponse{
		ScannedURL:         targetURL,
		FinalURL:           finalURL,
		RedirectCount:      redirectCount,
		HasInsecureSSL:     hasInsecureSSL,
		Score:              score,
		Grade:              grade,
		Headers:            headerResult.Headers,
		Cookies:            cookieResult.Cookies,
		HasSetCookie:       cookieResult.HasSetCookie,
		InformationLeakage: leakResult.Leaks,
		Config:             config,
	}, nil
}

// ===========================
// GRADE CALCULATOR
// ===========================

func calculateGrade(score int) string {
	switch {
	case score >= 90:
		return "A+"
	case score >= 80:
		return "A"
	case score >= 70:
		return "B"
	case score >= 60:
		return "C"
	case score >= 45:
		return "D"
	default:
		return "F"
	}
}

// ===========================
// HELPER: kiểm tra CSP yếu
// ===========================

func isWeakCSP(csp string) bool {
	lower := strings.ToLower(csp)
	weakPatterns := []string{
		"'unsafe-inline'",
		"'unsafe-eval'",
		"script-src *",     // chỉ flag wildcard ở script-src
		"default-src *",    // hoặc default-src wildcard
		"object-src *",     // hoặc object-src wildcard
		"script-src data:", // data: trong script-src mới nguy hiểm
	}
	for _, pattern := range weakPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
