// ============================================
// FILE: security-headers/handlers/handlers.go
//
// HTTP Handler cho Security Headers Analyzer (Gin)
// Pattern chuẩn theo ssl-checker/handlers/handler.go
//
// Error codes:
//   400 - Request không hợp lệ (input sai)
//   422 - Không thể phân giải domain
//   504 - Timeout
//   500 - Lỗi hệ thống
// ============================================

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
	"tools.bctechvibe.com/server/internal/modules/security-headers/service"
	"tools.bctechvibe.com/server/internal/platform/validator"
	response "tools.bctechvibe.com/server/internal/response"
)

// ===========================
// URL normalization
// ===========================

// normalizeURL đảm bảo URL luôn có scheme (mặc định https)
// và trích xuất hostname để validate.
func normalizeURL(input string) (string, string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", errors.New("URL trống")
	}

	// Thêm scheme nếu chưa có
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "https://" + input
	}

	// Bug #5 FIX: Dùng url.Parse thay vì url.ParseRequestURI
	// để hỗ trợ tốt hơn các edge case: path, query, port, special chars
	u, err := url.Parse(input)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", "", fmt.Errorf("URL không hợp lệ: %s", input)
	}

	hostname := u.Hostname()
	return u.String(), hostname, nil
}

// ===========================
// Main Handler
// ===========================

// HandleAnalyze xử lý POST /api/security-headers/analyze
func HandleAnalyze(c *gin.Context) {

	// 1. Bind JSON
	var req models.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Warn().Err(err).Msg("Security headers: invalid JSON body")
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// 2. Normalize URL
	targetURL, hostname, err := normalizeURL(req.TargetURL)
	if err != nil {
		log.Warn().Str("input", req.TargetURL).Err(err).Msg("Security headers: URL normalize failed")
		response.Error(c, http.StatusBadRequest, "Địa chỉ website không hợp lệ. Vui lòng kiểm tra lại URL.")
		return
	}

	// 3. Validate domain syntax
	if !validator.IsValidDomain(hostname) {
		log.Warn().Str("input", req.TargetURL).Str("hostname", hostname).Msg("Security headers: invalid domain format")
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền không hợp lệ")
		return
	}

	// 4. Anti-SSRF: chặn IP nội bộ / local
	if !validator.IsSafeHostname(hostname) {
		log.Warn().Str("input", req.TargetURL).Str("hostname", hostname).Msg("Security headers: SSRF blocked")
		response.Error(c, http.StatusBadRequest, "Tên miền/IP không được phép (Local/Internal)")
		return
	}

	// 5. Context timeout cho toàn bộ flow
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	// 6. Scan
	start := time.Now()
	result, err := service.Analyze(ctx, targetURL)
	duration := time.Since(start)

	if err != nil {
		handleScanError(c, err, targetURL)
		return
	}

	// 7. Log success
	log.Info().
		Str("url", targetURL).
		Str("final_url", result.FinalURL).
		Str("grade", result.Grade).
		Int("score", result.Score).
		Dur("duration", duration).
		Msg("Security headers scan success")

	// 8. Response
	response.SuccessNoMeta(c, result)
}

// ===========================
// Error classification
// ===========================

func handleScanError(c *gin.Context, err error, targetURL string) {

	// Timeout
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		log.Warn().Str("url", targetURL).Msg("Security headers: scan timeout")
		response.Error(c, http.StatusGatewayTimeout,
			fmt.Sprintf("Quá thời gian chờ phản hồi từ %s. Vui lòng thử lại.", targetURL))
		return
	}

	// TLS verification failed
	if errors.Is(err, service.ErrTLSFailed) {
		log.Warn().Err(err).Str("url", targetURL).Msg("Security headers: TLS verification failed")
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Chứng chỉ SSL/TLS của %s không hợp lệ hoặc đã hết hạn. Không thể quét bảo mật.", targetURL))
		return
	}

	// Connection refused / DNS fail
	if errors.Is(err, service.ErrConnectionFailed) {
		log.Warn().Err(err).Str("url", targetURL).Msg("Security headers: connection failed")
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Không thể kết nối đến %s. Kiểm tra tên miền hoặc website có đang hoạt động.", targetURL))
		return
	}

	// Fallback generic
	log.Error().Err(err).Str("url", targetURL).Msg("Security headers scan failed")
	response.Error(c, http.StatusInternalServerError,
		"Đã xảy ra lỗi hệ thống khi phân tích. Vui lòng thử lại sau.")
}
