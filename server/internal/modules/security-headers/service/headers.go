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
	"fmt"
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
	cspReportOnly := resp.Header.Get("Content-Security-Policy-Report-Only")
	if csp == "" {
		if cspReportOnly != "" {
			// Đang ở chế độ test — nhẹ hơn thiếu hoàn toàn
			penalty += 8
			headers = append(headers, models.HeaderResult{
				Name:         "Content-Security-Policy",
				Status:       models.StatusWarning,
				CurrentValue: "",
				Risk:         "Đang ở chế độ Report-Only (Test Mode). CSP chưa được áp dụng thực tế — trình duyệt chỉ báo cáo vi phạm, không chặn.",
				Fix:          "Chuyển từ Content-Security-Policy-Report-Only sang Content-Security-Policy khi đã hoàn tất kiểm tra.",
			})
		} else {
			// Hoàn toàn thiếu CSP
			penalty += 15
			headers = append(headers, models.HeaderResult{
				Name:         "Content-Security-Policy",
				Status:       models.StatusDanger,
				CurrentValue: "",
				Risk:         "Thiếu Content-Security-Policy. Có thể bị tấn công XSS hoặc Data Injection nghiêm trọng.",
				Fix:          "Cấu hình chính sách nguồn tài nguyên phù hợp với website.",
			})
			// Config: cung cấp 2 option (Basic + Compatible)
			nginx.WriteString("# [CSP] Basic (Safe)\n")
			nginx.WriteString("add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'\" always;\n")
			nginx.WriteString("# [CSP] Compatible (Cho website cũ)\n")
			nginx.WriteString("# add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'\" always;\n\n")

			apache.WriteString("# [CSP] Basic (Safe)\n")
			apache.WriteString("Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; form-action 'self'\"\n")
			apache.WriteString("# [CSP] Compatible (Cho website cũ)\n")
			apache.WriteString("# Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'\"\n\n")
		}
	} else {
		cspIssues := analyzeCSP(csp)
		if len(cspIssues) > 0 {
			hasHighSeverity := false
			hasPenalizedSeverity := false
			for _, issue := range cspIssues {
				if issue.Severity == "high" {
					hasHighSeverity = true
				} else if issue.Severity != "info" {
					hasPenalizedSeverity = true
				}
			}

			if hasHighSeverity {
				penalty += 10
				headers = append(headers, models.HeaderResult{
					Name:         "Content-Security-Policy",
					Status:       models.StatusDanger,
					CurrentValue: csp,
					Risk:         "Cấu hình CSP chứa các directive nguy hiểm (có thể dẫn đến XSS).",
					Fix:          "Siết chặt chính sách CSP, loại bỏ unsafe-inline, unsafe-eval và wildcard.",
					CSPIssues:    cspIssues,
				})
			} else if hasPenalizedSeverity {
				penalty += 3
				headers = append(headers, models.HeaderResult{
					Name:         "Content-Security-Policy",
					Status:       models.StatusWarning,
					CurrentValue: csp,
					Risk:         "CSP an toàn nhưng chưa tối ưu (thiếu một số directive bảo vệ hoặc có điểm yếu nhỏ).",
					CSPIssues:    cspIssues,
				})
			} else {
				headers = append(headers, models.HeaderResult{
					Name:         "Content-Security-Policy",
					Status:       models.StatusOK,
					CurrentValue: csp,
					Risk:         "Cấu hình CSP chặt chẽ và an toàn.",
					CSPIssues:    cspIssues,
				})
			}
		} else {
			headers = append(headers, models.HeaderResult{
				Name:         "Content-Security-Policy",
				Status:       models.StatusOK,
				CurrentValue: csp,
				Risk:         "Cấu hình CSP chặt chẽ và an toàn.",
			})
		}
	}

	// ─── 2. Strict-Transport-Security (HSTS) ───
	if finalScheme == "https" {
		hsts := resp.Header.Get("Strict-Transport-Security")
		hstsLower := strings.ToLower(hsts)

		// Parse max-age
		maxAgeVal := -1
		if strings.Contains(hstsLower, "max-age") {
			parts := strings.Split(hstsLower, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				kv := strings.SplitN(part, "=", 2)
				if len(kv) == 2 && strings.TrimSpace(kv[0]) == "max-age" {
					var val int
					if _, err := fmt.Sscanf(strings.TrimSpace(kv[1]), "%d", &val); err == nil {
						maxAgeVal = val
					}
				}
			}
		}

		if hsts == "" {
			penalty += 15
			headers = append(headers, models.HeaderResult{
				Name:         "Strict-Transport-Security",
				Status:       models.StatusDanger,
				CurrentValue: "",
				Risk:         "Nguy cơ bị tấn công MITM (Downgrade Attack từ HTTPS xuống HTTP).",
				Fix:          "Bắt buộc trình duyệt luôn sử dụng HTTPS.",
			})
			nginx.WriteString("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n")
			apache.WriteString("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n")
		} else if maxAgeVal <= 0 {
			penalty += 15
			headers = append(headers, models.HeaderResult{
				Name:         "Strict-Transport-Security",
				Status:       models.StatusDanger,
				CurrentValue: hsts,
				Risk:         "HSTS đang bị tắt hoặc có giá trị max-age không hợp lệ (max-age=0), không thể bảo vệ khỏi Downgrade Attack.",
				Fix:          "Cấu hình max-age lớn hơn 0 (khuyến nghị tối thiểu là 31536000 giây - 1 năm).",
			})
			nginx.WriteString("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n")
			apache.WriteString("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n")
		} else {
			// Check for Preload readiness
			hasIncludeSubdomains := false
			hasPreload := false
			
			parts := strings.Split(hstsLower, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part == "includesubdomains" {
					hasIncludeSubdomains = true
				}
				if part == "preload" {
					hasPreload = true
				}
			}
			
			if maxAgeVal >= 31536000 && hasIncludeSubdomains {
				if hasPreload {
					headers = append(headers, models.HeaderResult{
						Name:         "Strict-Transport-Security",
						Status:       models.StatusOK,
						CurrentValue: hsts,
						Risk:         "An toàn tối đa (Header đạt điều kiện cú pháp cho HSTS Preload).",
					})
				} else {
					headers = append(headers, models.HeaderResult{
						Name:         "Strict-Transport-Security",
						Status:       models.StatusOK,
						CurrentValue: hsts,
						Risk:         "An toàn cao (Đạt chuẩn max-age và includeSubDomains, thiếu preload nhưng là tuỳ chọn).",
						Fix:          "Optional: Thêm preload nếu bạn có ý định đăng ký HSTS Preload dài hạn.",
					})
				}
			} else {
				var missing []string
				if maxAgeVal < 31536000 {
					missing = append(missing, "max-age >= 31536000")
				}
				if !hasIncludeSubdomains {
					missing = append(missing, "includeSubDomains")
				}
				
				headers = append(headers, models.HeaderResult{
					Name:         "Strict-Transport-Security",
					Status:       models.StatusWarning,
					CurrentValue: hsts,
					Risk:         "An toàn cơ bản, nhưng chưa đủ điều kiện tối ưu. Thiếu: " + strings.Join(missing, ", "),
					Fix:          "Khuyến nghị tăng max-age lên tối thiểu 31536000 và thêm includeSubDomains.",
				})
				penalty += 2 // Phạt nhẹ
			}
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
		nginx.WriteString("add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n")
		apache.WriteString("# [HSTS] Yêu cầu HTTPS trước khi bật HSTS\n")
		apache.WriteString("Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n")
	}

	// ─── 3. X-Frame-Options ───
	xFrame := strings.TrimSpace(strings.ToLower(resp.Header.Get("X-Frame-Options")))
	csp = resp.Header.Get("Content-Security-Policy")
	hasFrameAncestors := hasSecureFrameAncestors(csp)

	if xFrame == "" {
		if hasFrameAncestors {
			headers = append(headers, models.HeaderResult{
				Name:         "X-Frame-Options",
				Status:       models.StatusOK,
				CurrentValue: "",
				Risk:         "Không có X-Frame-Options nhưng đã được bảo vệ bởi CSP frame-ancestors (hiện đại và an toàn hơn).",
			})
		} else {
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
		}
	} else if xFrame != "deny" && xFrame != "sameorigin" {
		penalty += 10
		headers = append(headers, models.HeaderResult{
			Name:         "X-Frame-Options",
			Status:       models.StatusDanger,
			CurrentValue: resp.Header.Get("X-Frame-Options"),
			Risk:         "Giá trị X-Frame-Options không hợp lệ hoặc quá yếu (chỉ chấp nhận 'DENY' hoặc 'SAMEORIGIN'), không thể phòng tránh tấn công Clickjacking.",
			Fix:          "Cấu hình X-Frame-Options về 'DENY' hoặc 'SAMEORIGIN'.",
		})
		nginx.WriteString("add_header X-Frame-Options \"SAMEORIGIN\" always;\n")
		apache.WriteString("Header always set X-Frame-Options \"SAMEORIGIN\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "X-Frame-Options",
			Status:       models.StatusOK,
			CurrentValue: resp.Header.Get("X-Frame-Options"),
			Risk:         "An toàn.",
		})
	}

	// ─── 4. X-Content-Type-Options ───
	xContent := strings.TrimSpace(strings.ToLower(resp.Header.Get("X-Content-Type-Options")))
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
	} else if xContent != "nosniff" {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "X-Content-Type-Options",
			Status:       models.StatusWarning,
			CurrentValue: resp.Header.Get("X-Content-Type-Options"),
			Risk:         "Giá trị X-Content-Type-Options không hợp lệ (chỉ chấp nhận 'nosniff'), trình duyệt vẫn có thể tự suy đoán MIME-type.",
			Fix:          "Cấu hình X-Content-Type-Options chính xác thành 'nosniff'.",
		})
		nginx.WriteString("add_header X-Content-Type-Options \"nosniff\" always;\n")
		apache.WriteString("Header always set X-Content-Type-Options \"nosniff\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "X-Content-Type-Options",
			Status:       models.StatusOK,
			CurrentValue: resp.Header.Get("X-Content-Type-Options"),
			Risk:         "An toàn.",
		})
	}

	// ─── 5. Referrer-Policy ───
	referrer := strings.TrimSpace(strings.ToLower(resp.Header.Get("Referrer-Policy")))
	isValidReferrer := referrer == "no-referrer" ||
		referrer == "no-referrer-when-downgrade" ||
		referrer == "origin" ||
		referrer == "origin-when-cross-origin" ||
		referrer == "same-origin" ||
		referrer == "strict-origin" ||
		referrer == "strict-origin-when-cross-origin"

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
	} else if referrer == "unsafe-url" || !isValidReferrer {
		penalty += 5
		status := models.StatusWarning
		if referrer == "unsafe-url" {
			status = models.StatusDanger
		}
		headers = append(headers, models.HeaderResult{
			Name:         "Referrer-Policy",
			Status:       status,
			CurrentValue: resp.Header.Get("Referrer-Policy"),
			Risk:         "Referrer-Policy rỗng hoặc có giá trị quá yếu/không hợp lệ (ví dụ 'unsafe-url' làm rò rỉ toàn bộ URL chứa dữ liệu nhạy cảm qua http).",
			Fix:          "Cấu hình Referrer-Policy thành các giá trị an toàn hơn như 'strict-origin-when-cross-origin' hoặc 'no-referrer'.",
		})
		nginx.WriteString("add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;\n")
		apache.WriteString("Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "Referrer-Policy",
			Status:       models.StatusOK,
			CurrentValue: resp.Header.Get("Referrer-Policy"),
			Risk:         "An toàn.",
		})
	}

	// ─── 6. Permissions-Policy ───
	permissions := resp.Header.Get("Permissions-Policy")
	isValidPermissions := true
	if permissions != "" {
		parts := strings.Split(permissions, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.Split(part, "=")
			if len(kv) != 2 {
				isValidPermissions = false
				break
			}
			val := strings.TrimSpace(kv[1])
			if !strings.HasPrefix(val, "(") || !strings.HasSuffix(val, ")") {
				isValidPermissions = false
				break
			}
		}
	} else {
		isValidPermissions = false
	}

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
	} else if !isValidPermissions {
		penalty += 5
		headers = append(headers, models.HeaderResult{
			Name:         "Permissions-Policy",
			Status:       models.StatusWarning,
			CurrentValue: permissions,
			Risk:         "Cú pháp Permissions-Policy không hợp lệ hoặc không an toàn (ví dụ: thiếu dấu ngoặc đơn bọc ngoài allowlist của feature, ví dụ đúng: camera=()).",
			Fix:          "Cấu hình Permissions-Policy chính xác, ví dụ: camera=(), microphone=().",
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

	// ─── 7. Cross-Origin-Opener-Policy (COOP) ───
	coop := strings.TrimSpace(strings.ToLower(resp.Header.Get("Cross-Origin-Opener-Policy")))
	isValidCOOP := coop == "same-origin" || coop == "same-origin-allow-popups" || coop == "restrict-properties"

	if coop == "" {
		// COOP là header tuỳ chọn, không bắt buộc trừ điểm
		headers = append(headers, models.HeaderResult{
			Name:         "Cross-Origin-Opener-Policy",
			Status:       models.StatusWarning, // Giữ warning nhưng không phạt
			CurrentValue: "",
			Risk:         "Thiếu COOP: website có thể bị tấn công cross-origin qua cửa sổ trình duyệt dùng chung (Shared Browsing Context).",
			Fix:          "Optional: Cô lập context trình duyệt để bảo vệ khỏi tấn công Spectre.",
		})
		nginx.WriteString("add_header Cross-Origin-Opener-Policy \"same-origin\" always;\n")
		apache.WriteString("Header always set Cross-Origin-Opener-Policy \"same-origin\"\n")
	} else if coop == "unsafe-none" || !isValidCOOP {
		// Vẫn cảnh báo nếu cấu hình sai hoặc quá yếu, nhưng không phạt
		headers = append(headers, models.HeaderResult{
			Name:         "Cross-Origin-Opener-Policy",
			Status:       models.StatusWarning,
			CurrentValue: resp.Header.Get("Cross-Origin-Opener-Policy"),
			Risk:         "Giá trị Cross-Origin-Opener-Policy không hợp lệ hoặc quá yếu (chỉ chấp nhận 'same-origin', 'same-origin-allow-popups' hoặc 'restrict-properties').",
			Fix:          "Cấu hình Cross-Origin-Opener-Policy thành 'same-origin' hoặc 'same-origin-allow-popups'.",
		})
		nginx.WriteString("add_header Cross-Origin-Opener-Policy \"same-origin\" always;\n")
		apache.WriteString("Header always set Cross-Origin-Opener-Policy \"same-origin\"\n")
	} else {
		headers = append(headers, models.HeaderResult{
			Name:         "Cross-Origin-Opener-Policy",
			Status:       models.StatusOK,
			CurrentValue: resp.Header.Get("Cross-Origin-Opener-Policy"),
			Risk:         "An toàn.",
		})
	}

	finalApacheConfig := apache.String()
	if finalApacheConfig != "" {
		finalApacheConfig = "# Requires mod_headers\n" + finalApacheConfig
	}

	return HeaderAnalysisResult{
		Headers:      headers,
		Penalty:      penalty,
		NginxConfig:  nginx.String(),
		ApacheConfig: finalApacheConfig,
	}
}
