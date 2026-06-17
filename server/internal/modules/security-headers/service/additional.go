// ============================================
// FILE: security-headers/service/additional.go
//
// Phân tích các header informational (không tính điểm):
//   - Content-Security-Policy-Report-Only
//   - X-XSS-Protection (deprecated)
//   - Cross-Origin-Embedder-Policy (modern / optional)
//   - Cross-Origin-Resource-Policy (modern / optional)
//   - Reporting-Endpoints / Report-To (Reporting API)
//   - Network Error Logging (NEL)
//   - Expect-CT (deprecated)
//   - Feature-Policy (deprecated)
// ============================================

package service

import (
	"encoding/json"
	"net/http"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

// analyzeAdditionalHeaders phân tích các header informational — không trừ điểm
func analyzeAdditionalHeaders(resp *http.Response) []models.AdditionalHeaderResult {
	var results []models.AdditionalHeaderResult

	// ─── 1. Content-Security-Policy-Report-Only ───
	cspRO := resp.Header.Get("Content-Security-Policy-Report-Only")
	if cspRO != "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Content-Security-Policy-Report-Only",
			Value:       cspRO,
			Present:     true,
			Status:      "info",
			Description: "Đang chạy ở chế độ Test CSP (Report-Only). Trình duyệt ghi nhận vi phạm nhưng không chặn. Hãy chuyển sang Content-Security-Policy sau khi hoàn tất kiểm tra.",
		})
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Content-Security-Policy-Report-Only",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Không có. Nếu muốn triển khai CSP an toàn, hãy dùng header này để kiểm thử chính sách trước khi bật thật.",
		})
	}

	// ─── 2. X-XSS-Protection (deprecated) ───
	xss := resp.Header.Get("X-XSS-Protection")
	if xss == "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "X-XSS-Protection",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header cũ, đã bị deprecated. Không cần thiết lập nếu đã có CSP tốt.",
		})
	} else if strings.TrimSpace(xss) == "0" {
		// Tắt đúng cách — OK
		results = append(results, models.AdditionalHeaderResult{
			Name:        "X-XSS-Protection",
			Value:       xss,
			Present:     true,
			Status:      "ok",
			Description: "Đã tắt đúng cách (= 0). Header này deprecated từ 2020 — tắt là lựa chọn đúng để tránh lỗi trình duyệt.",
		})
	} else {
		// Đang bật mode cũ (1 hoặc 1; mode=block) — không khuyến nghị
		results = append(results, models.AdditionalHeaderResult{
			Name:        "X-XSS-Protection",
			Value:       xss,
			Present:     true,
			Status:      "deprecated",
			Description: "Header đã deprecated từ 2020. Nên đặt thành \"0\" để vô hiệu hóa hoặc xóa bỏ hẳn. Dùng Content-Security-Policy thay thế.",
		})
	}

	// ─── 3. Cross-Origin-Embedder-Policy (COEP) — Modern / Optional ───
	coep := resp.Header.Get("Cross-Origin-Embedder-Policy")
	coepLower := strings.TrimSpace(strings.ToLower(coep))
	if coep != "" {
		if coepLower == "require-corp" || coepLower == "credentialless" {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Embedder-Policy",
				Value:       coep,
				Present:     true,
				Status:      "ok",
				Description: "COEP hợp lệ. Hỗ trợ đạt trạng thái Cross-Origin Isolation để bật Web API hiện đại (ví dụ: SharedArrayBuffer).",
			})
		} else if coepLower == "unsafe-none" {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Embedder-Policy",
				Value:       coep,
				Present:     true,
				Status:      "info",
				Description: "COEP được đặt thành unsafe-none (mặc định), không bật Cross-Origin Isolation.",
			})
		} else {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Embedder-Policy",
				Value:       coep,
				Present:     true,
				Status:      "warning",
				Description: "Giá trị COEP không hợp lệ. Chỉ nên dùng 'require-corp', 'credentialless' hoặc 'unsafe-none'.",
			})
		}
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Cross-Origin-Embedder-Policy",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header hiện đại (Modern / Optional). Cần thiết nếu website dùng SharedArrayBuffer hoặc muốn đạt Cross-Origin Isolation.",
		})
	}

	// ─── 4. Cross-Origin-Resource-Policy (CORP) — Modern / Optional ───
	corp := resp.Header.Get("Cross-Origin-Resource-Policy")
	corpLower := strings.TrimSpace(strings.ToLower(corp))
	if corp != "" {
		if corpLower == "same-origin" || corpLower == "same-site" {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Resource-Policy",
				Value:       corp,
				Present:     true,
				Status:      "ok",
				Description: "CORP hợp lệ. Bảo vệ mạnh mẽ tài nguyên khỏi các cuộc tấn công Spectre và side-channel (không cho phép load cross-origin).",
			})
		} else if corpLower == "cross-origin" {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Resource-Policy",
				Value:       corp,
				Present:     true,
				Status:      "info",
				Description: "CORP hợp lệ. Tài nguyên được phép load cross-origin (nới lỏng), phù hợp cho tài nguyên public/CDN.",
			})
		} else {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "Cross-Origin-Resource-Policy",
				Value:       corp,
				Present:     true,
				Status:      "warning",
				Description: "Giá trị CORP không hợp lệ. Chỉ nên dùng 'same-origin', 'same-site' hoặc 'cross-origin'.",
			})
		}
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Cross-Origin-Resource-Policy",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header hiện đại (Modern / Optional). Ngăn chặn cross-origin loading tài nguyên — đặc biệt quan trọng với API endpoints.",
		})
	}

	// ─── 5. Reporting API (Report-To & Reporting-Endpoints) ───
	reportTo := resp.Header.Get("Report-To")
	reportingEndpoints := resp.Header.Get("Reporting-Endpoints")

	if reportingEndpoints != "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Reporting-Endpoints",
			Value:       reportingEndpoints,
			Present:     true,
			Status:      "ok",
			Description: "Reporting API hiện đại được cấu hình. Trình duyệt sẽ gửi báo cáo lỗi bảo mật (CSP, COEP, v.v.) về endpoint này.",
		})
	} else if reportTo != "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Report-To",
			Value:       reportTo,
			Present:     true,
			Status:      "info",
			Description: "Đang sử dụng Report-To. Header này dần được coi là legacy. Tùy thuộc vào trình duyệt, nên chuyển sang hoặc bổ sung Reporting-Endpoints để tương thích tốt hơn.",
		})
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Reporting-Endpoints",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Không có Reporting API. Nếu muốn nhận báo cáo vi phạm bảo mật tự động, hãy cấu hình header Reporting-Endpoints.",
		})
	}

	// ─── 6. Network Error Logging (NEL) ───
	nel := resp.Header.Get("NEL")
	if nel != "" {
		// Validate JSON
		var nelObj map[string]interface{}
		isValid := false
		if err := json.Unmarshal([]byte(nel), &nelObj); err == nil {
			if _, ok := nelObj["max_age"].(float64); ok {
				isValid = true
			}
		}

		if isValid {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "NEL",
				Value:       nel,
				Present:     true,
				Status:      "ok",
				Description: "NEL (Network Error Logging) được cấu hình hợp lệ. Trình duyệt sẽ báo cáo các lỗi mạng liên quan đến trang web.",
			})
		} else {
			results = append(results, models.AdditionalHeaderResult{
				Name:        "NEL",
				Value:       nel,
				Present:     true,
				Status:      "warning",
				Description: "Giá trị NEL không hợp lệ (phải là cấu trúc JSON hợp lệ và có trường max_age dạng số).",
			})
		}
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "NEL",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header ghi nhận lỗi mạng. Kết hợp cùng Reporting API để nhận báo cáo lỗi mạng từ người dùng.",
		})
	}

	// ─── 7. Expect-CT ───
	expectCT := resp.Header.Get("Expect-CT")
	if expectCT != "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Expect-CT",
			Value:       expectCT,
			Present:     true,
			Status:      "deprecated",
			Description: "Expect-CT đã bị deprecated do Certificate Transparency (CT) đã được yêu cầu mặc định bởi các trình duyệt.",
		})
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Expect-CT",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header đã deprecated. Tính năng Certificate Transparency đã được trình duyệt ép buộc mặc định nên không cần Expect-CT nữa.",
		})
	}

	// ─── 8. Feature-Policy ───
	featurePolicy := resp.Header.Get("Feature-Policy")
	if featurePolicy != "" {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Feature-Policy",
			Value:       featurePolicy,
			Present:     true,
			Status:      "deprecated",
			Description: "Feature-Policy đã bị đổi tên thành Permissions-Policy. Vui lòng cập nhật header này.",
		})
	} else {
		results = append(results, models.AdditionalHeaderResult{
			Name:        "Feature-Policy",
			Value:       "",
			Present:     false,
			Status:      "info",
			Description: "Header cũ của Permissions-Policy. Không còn cần thiết, hãy sử dụng Permissions-Policy.",
		})
	}

	return results
}
