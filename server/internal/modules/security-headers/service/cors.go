// ============================================
// FILE: security-headers/service/cors.go
//
// Phân tích CORS qua Active Probing
//   - Gửi GET request kèm Origin giả mạo (https://evil-bctechvibe.com)
//   - Check Access-Control-Allow-Origin và Access-Control-Allow-Credentials
// ============================================

package service

import (
	"context"
	"io"
	"net/http"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

type internalCORSAnalysis struct {
	Data    models.CORSAnalysisResult
	Penalty int
}

func analyzeCORS(ctx context.Context, targetURL string) internalCORSAnalysis {
	result := models.CORSAnalysisResult{
		Enabled: false,
		Issues:  []models.CORSResult{},
	}
	penalty := 0

	fakeOrigin := "https://evil-bctechvibe.com"

	// Sử dụng client không follow redirect
	client := noRedirectClient

	// Flag để theo dõi xem CORS có được kích hoạt ở bất kỳ probe nào không
	corsEnabled := false

	// --- 1. Simple GET Probe ---
	reqSimple, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		result.Error = "Lỗi khởi tạo request CORS: " + err.Error()
		return internalCORSAnalysis{Data: result, Penalty: penalty}
	}
	reqSimple.Header.Set("User-Agent", userAgent)
	reqSimple.Header.Set("Origin", fakeOrigin)
	reqSimple.Header.Set("Accept", "*/*")

	respSimple, err := client.Do(reqSimple)
	if err != nil {
		result.Error = "Kết nối thất bại hoặc bị WAF chặn: " + err.Error()
		return internalCORSAnalysis{Data: result, Penalty: penalty}
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(respSimple.Body, 1024))
		respSimple.Body.Close()
	}()

	acaoSimple := strings.TrimSpace(respSimple.Header.Get("Access-Control-Allow-Origin"))
	acacSimple := strings.TrimSpace(strings.ToLower(respSimple.Header.Get("Access-Control-Allow-Credentials")))
	varySimple := strings.TrimSpace(strings.ToLower(respSimple.Header.Get("Vary")))

	if acaoSimple != "" {
		corsEnabled = true
	}

	hasCredentialsSimple := acacSimple == "true"
	reflectsOriginSimple := acaoSimple == fakeOrigin
	isWildcardSimple := acaoSimple == "*"
	hasVaryOriginSimple := false
	for _, token := range strings.Split(varySimple, ",") {
		token = strings.TrimSpace(token)
		if token == "origin" || token == "*" {
			hasVaryOriginSimple = true
			break
		}
	}

	// 1. Wildcard + Credentials
	if isWildcardSimple && hasCredentialsSimple {
		penalty += 15
		result.Issues = append(result.Issues, models.CORSResult{
			Status:      models.StatusDanger,
			Description: "Simple Request: Wildcard (*) kết hợp với Allow-Credentials: true",
			Risk:        "Trình duyệt có thể từ chối request này theo spec, nhưng việc cấu hình server mở hoàn toàn CORS kèm thông tin định danh là cực kỳ nguy hiểm.",
			Fix:         "Không bao giờ dùng '*' khi có Allow-Credentials.",
		})
	}

	// 2. Reflects Fake Origin + Credentials
	if reflectsOriginSimple && hasCredentialsSimple {
		penalty += 20
		result.Issues = append(result.Issues, models.CORSResult{
			Status:      models.StatusDanger,
			Description: "Simple Request: Tự động phản hồi Origin lạ kèm Allow-Credentials: true",
			Risk:        "LỖ HỔNG NGHIÊM TRỌNG: Kẻ tấn công có thể dụ người dùng truy cập trang độc hại và đánh cắp dữ liệu/phiên làm việc (session cookies).",
			Fix:         "Xác thực Origin từ danh sách Whitelist ở Backend thay vì phản hồi tự động.",
		})
	}

	// 3. Reflects Fake Origin (No Credentials)
	if reflectsOriginSimple && !hasCredentialsSimple {
		penalty += 5
		result.Issues = append(result.Issues, models.CORSResult{
			Status:      models.StatusWarning,
			Description: "Simple Request: Tự động phản hồi (Reflect) Origin lạ",
			Risk:        "Mở CORS cho bất kỳ ai có thể dẫn đến lạm dụng tài nguyên công khai hoặc bị attacker đọc dữ liệu nội bộ.",
			Fix:         "Chỉ định danh sách Origin cụ thể nếu nội dung không dành cho public.",
		})
	}

	// 4. Missing Vary: Origin
	if reflectsOriginSimple && !hasVaryOriginSimple {
		penalty += 5
		result.Issues = append(result.Issues, models.CORSResult{
			Status:      models.StatusWarning,
			Description: "Thiếu 'Vary: Origin' khi cấu hình CORS động",
			Risk:        "CDN/Cache có thể trả về nhầm Access-Control-Allow-Origin cho người dùng khác, gây lỗi CORS ngẫu nhiên.",
			Fix:         "Thêm 'Vary: Origin' vào header phản hồi.",
		})
	}

	// --- 2. Preflight OPTIONS Probe ---
	dangerousMethods := []string{"PUT", "DELETE", "PATCH"}
	preflightIssueReported := false

	for _, method := range dangerousMethods {
		if preflightIssueReported {
			break
		}

		reqOptions, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
		if err != nil {
			continue
		}
		
		reqOptions.Header.Set("User-Agent", userAgent)
		reqOptions.Header.Set("Origin", fakeOrigin)
		reqOptions.Header.Set("Access-Control-Request-Method", method)
		reqOptions.Header.Set("Access-Control-Request-Headers", "X-Custom-Header")

		respOptions, err := client.Do(reqOptions)
		if err == nil {
			acaoOptions := strings.TrimSpace(respOptions.Header.Get("Access-Control-Allow-Origin"))
			acamOptions := strings.TrimSpace(respOptions.Header.Get("Access-Control-Allow-Methods"))
			
			// drain body
			io.Copy(io.Discard, io.LimitReader(respOptions.Body, 1024))
			respOptions.Body.Close()

			if acaoOptions != "" {
				corsEnabled = true
				if acaoOptions == fakeOrigin || acaoOptions == "*" {
					methods := strings.Split(acamOptions, ",")
					hasDangerousMethod := false
					for _, m := range methods {
						m = strings.ToUpper(strings.TrimSpace(m))
						if m == "*" || m == "PUT" || m == "DELETE" || m == "PATCH" {
							hasDangerousMethod = true
							break
						}
					}
					
					if hasDangerousMethod {
						penalty += 10
						result.Issues = append(result.Issues, models.CORSResult{
							Status:      models.StatusDanger,
							Description: "Preflight Request: Cho phép Origin lạ kèm các Methods nguy hiểm (VD: PUT, DELETE)",
							Risk:        "Attacker có thể gửi yêu cầu thay đổi dữ liệu từ cross-origin.",
							Fix:         "Giới hạn Methods cho từng Origin hợp lệ trong luồng Preflight.",
						})
						preflightIssueReported = true
					}
				}
			}
		}
	}

	// --- 3. Null Origin Probe ---
	reqNull, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err == nil {
		reqNull.Header.Set("User-Agent", userAgent)
		reqNull.Header.Set("Origin", "null")
		
		respNull, err := client.Do(reqNull)
		if err == nil {
			defer func() {
				io.Copy(io.Discard, io.LimitReader(respNull.Body, 1024))
				respNull.Body.Close()
			}()

			acaoNull := strings.TrimSpace(respNull.Header.Get("Access-Control-Allow-Origin"))
			acacNull := strings.TrimSpace(strings.ToLower(respNull.Header.Get("Access-Control-Allow-Credentials")))

			if acaoNull != "" {
				corsEnabled = true
				if acaoNull == "null" {
					penalty += 15
					issueRisk := "Local HTML files, iframe sandboxes, hoặc attacker có thể bypass whitelist bằng cách ép Origin: null."
					issueFix := "Tránh trả về Access-Control-Allow-Origin: null. Kiểm tra strict logic trong code."
					
					if acacNull == "true" {
						penalty += 10 // Thêm phạt vì có credentials
						result.Issues = append(result.Issues, models.CORSResult{
							Status:      models.StatusDanger,
							Description: "Null Origin Bypass: Chấp nhận 'null' kèm Allow-Credentials",
							Risk:        "Cực kỳ nguy hiểm: " + issueRisk,
							Fix:         issueFix,
						})
					} else {
						result.Issues = append(result.Issues, models.CORSResult{
							Status:      models.StatusWarning,
							Description: "Null Origin Bypass: Chấp nhận Origin là 'null'",
							Risk:        issueRisk,
							Fix:         issueFix,
						})
					}
				} else if acaoNull == "*" {
					penalty += 5
					result.Issues = append(result.Issues, models.CORSResult{
						Status:      models.StatusWarning,
						Description: "Null Origin Probe: Phản hồi wildcard (*) cho Origin 'null'",
						Risk:        "Policy quá rộng, tuy không gửi được credentials nhưng mở dữ liệu cho mọi đối tượng public.",
						Fix:         "Chỉ trả về '*' nếu tài nguyên thực sự cần public. Tốt nhất nên whitelist domain cụ thể.",
					})
				}
			}
		}
	}

	if !corsEnabled {
		return internalCORSAnalysis{Data: result, Penalty: penalty}
	}

	result.Enabled = true

	if len(result.Issues) == 0 {
		result.Issues = append(result.Issues, models.CORSResult{
			Status:      models.StatusOK,
			Description: "Cấu hình CORS cơ bản an toàn.",
		})
	}

	// Cap điểm trừ
	if penalty > 25 {
		penalty = 25
	}

	return internalCORSAnalysis{
		Data:    result,
		Penalty: penalty,
	}
}
