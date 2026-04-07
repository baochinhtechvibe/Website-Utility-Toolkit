// ============================================
// FILE: security-headers/service/headers.go
//
// Phân tích 6 header bảo mật chính:
//   1. Content-Security-Policy (CSP)
//   2. Strict-Transport-Security (HSTS)
//   3. X-Frame-Options
//   4. X-Content-Type-Options
//   5. Referrer-Policy
//   6. Permissions-Policy
//
// Trả về: danh sách kết quả + tổng điểm trừ + config Nginx/Apache
// ============================================

package service

import (
	"net/http"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

// HeaderAnalysisResult chứa output của phân tích header
type HeaderAnalysisResult struct {
	Headers      []models.HeaderResult
	Penalty      int
	NginxConfig  string
	ApacheConfig string
}

// analyzeHeaders phân tích 6 header bảo mật trên response cuối cùng
func analyzeHeaders(resp *http.Response, finalScheme string) HeaderAnalysisResult {
	var headers []models.HeaderResult
	var penalty int
	var nginx strings.Builder
	var apache strings.Builder

	// ─── 1. Content-Security-Policy ───
	csp := resp.Header.Get("Content-Security-Policy")
	if csp == "" {
		penalty += 10
		headers = append(headers, models.HeaderResult{
			Name:         "Content-Security-Policy",
			Status:       models.StatusWarning,
			CurrentValue: "",
			Risk:         "Thiếu Content-Security-Policy. Có thể bị tấn công XSS hoặc Data Injection.",
			Fix:          "Cấu hình chính sách nguồn tài nguyên.",
		})
		// Config: cung cấp 2 option (Basic + Compatible)
		nginx.WriteString("# [CSP] Basic (Safe)\n")
		nginx.WriteString("add_header Content-Security-Policy \"default-src 'self'\" always;\n")
		nginx.WriteString("# [CSP] Compatible (Cho website cũ)\n")
		nginx.WriteString("# add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'\" always;\n\n")

		apache.WriteString("# [CSP] Basic (Safe)\n")
		apache.WriteString("Header always set Content-Security-Policy \"default-src 'self'\"\n")
		apache.WriteString("# [CSP] Compatible (Cho website cũ)\n")
		apache.WriteString("# Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'\"\n\n")
	} else if isWeakCSP(csp) {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "Content-Security-Policy",
			Status:       models.StatusWarning,
			CurrentValue: csp,
			Risk:         "CSP nới lỏng quá mức (chứa unsafe-inline, unsafe-eval hoặc wildcard *).",
			Fix:          "Siết chặt chính sách CSP, loại bỏ unsafe-inline và wildcard.",
		})
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "Content-Security-Policy",
			Status:       models.StatusOK,
			CurrentValue: csp,
			Risk:         "An toàn.",
		})
	}

	// ─── 2. Strict-Transport-Security (HSTS) ───
	if finalScheme == "https" {
		hsts := resp.Header.Get("Strict-Transport-Security")
		if hsts == "" {
			penalty += 15
			headers = append(headers, models.HeaderResult{
				Name:         "Strict-Transport-Security",
				Status:       models.StatusDanger,
				CurrentValue: "",
				Risk:         "Nguy cơ bị tấn công MITM (Downgrade Attack từ HTTPS xuống HTTP).",
				Fix:          "Bắt buộc trình duyệt luôn sử dụng HTTPS.",
			})
			nginx.WriteString("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n")
			apache.WriteString("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
		} else {
			headers = append(headers, models.HeaderResult{
				Name:         "Strict-Transport-Security",
				Status:       models.StatusOK,
				CurrentValue: hsts,
				Risk:         "An toàn.",
			})
		}
	} else {
		// Site serve qua HTTP thuần — HSTS không có hiệu lực, đây là rủi ro nghiêm trọng
		penalty += 15
		headers = append(headers, models.HeaderResult{
			Name:         "Strict-Transport-Security",
			Status:       models.StatusDanger,
			CurrentValue: "",
			Risk:         "Website đang phục vụ qua HTTP thuần — HSTS không có hiệu lực. Nên chuyển sang HTTPS.",
			Fix:          "Chuyển website sang HTTPS và thêm header HSTS.",
		})
		nginx.WriteString("# [HSTS] Yêu cầu HTTPS trước khi bật HSTS\n")
		nginx.WriteString("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n")
		apache.WriteString("# [HSTS] Yêu cầu HTTPS trước khi bật HSTS\n")
		apache.WriteString("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n")
	}

	// ─── 3. X-Frame-Options ───
	xFrame := resp.Header.Get("X-Frame-Options")
	if xFrame == "" {
		penalty += 10
		headers = append(headers, models.HeaderResult{
			Name:         "X-Frame-Options",
			Status:       models.StatusDanger,
			CurrentValue: "",
			Risk:         "Nguy cơ bị tấn công Clickjacking (website có thể bị nhúng vào iframe độc hại).",
			Fix:          "Chặn website bị nhúng vào iframe từ domain khác.",
		})
		nginx.WriteString("add_header X-Frame-Options \"SAMEORIGIN\" always;\n")
		apache.WriteString("Header always set X-Frame-Options \"SAMEORIGIN\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "X-Frame-Options",
			Status:       models.StatusOK,
			CurrentValue: xFrame,
			Risk:         "An toàn.",
		})
	}

	// ─── 4. X-Content-Type-Options ───
	xContent := resp.Header.Get("X-Content-Type-Options")
	if xContent == "" {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "X-Content-Type-Options",
			Status:       models.StatusWarning,
			CurrentValue: "",
			Risk:         "Thiếu best practice: trình duyệt có thể tự suy đoán MIME type (MIME-sniffing).",
			Fix:          "Ngăn trình duyệt tự đoán loại nội dung.",
		})
		nginx.WriteString("add_header X-Content-Type-Options \"nosniff\" always;\n")
		apache.WriteString("Header always set X-Content-Type-Options \"nosniff\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "X-Content-Type-Options",
			Status:       models.StatusOK,
			CurrentValue: xContent,
			Risk:         "An toàn.",
		})
	}

	// ─── 5. Referrer-Policy ───
	referrer := resp.Header.Get("Referrer-Policy")
	if referrer == "" {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "Referrer-Policy",
			Status:       models.StatusWarning,
			CurrentValue: "",
			Risk:         "Thiếu best practice: có thể rò rỉ thông tin URL khi điều hướng sang trang khác.",
			Fix:          "Giới hạn thông tin Referrer gửi ra ngoài.",
		})
		nginx.WriteString("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n")
		apache.WriteString("Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "Referrer-Policy",
			Status:       models.StatusOK,
			CurrentValue: referrer,
			Risk:         "An toàn.",
		})
	}

	// ─── 6. Permissions-Policy ───
	permissions := resp.Header.Get("Permissions-Policy")
	if permissions == "" {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "Permissions-Policy",
			Status:       models.StatusWarning,
			CurrentValue: "",
			Risk:         "Thiếu best practice: trình duyệt có thể truy cập Camera, Microphone nếu bị XSS.",
			Fix:          "Khóa các quyền trình duyệt không cần thiết.",
		})
		nginx.WriteString("add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;\n")
		apache.WriteString("Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "Permissions-Policy",
			Status:       models.StatusOK,
			CurrentValue: permissions,
			Risk:         "An toàn.",
		})
	}

	return HeaderAnalysisResult{
		Headers:      headers,
		Penalty:      penalty,
		NginxConfig:  nginx.String(),
		ApacheConfig: apache.String(),
	}
}
