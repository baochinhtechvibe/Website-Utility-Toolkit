package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/models"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/service"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

// logSanitizer khởi tạo 1 lần để dùng chung (Quy tắc #48)
var logSanitizer = strings.NewReplacer("\n", "", "\r", "", "\t", "")

// HandleScan xử lý POST /api/mixed-content/scan
func HandleScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// 1. Áp dụng Timeout 20s (Quy tắc #41)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	data, err, isCached, fetchedAt := service.ScanMixedContent(ctx, req, c.ClientIP())
	if err != nil {
		// 2. Sanitize URL trước khi log (Quy tắc #40) - Dùng pre-allocated sanitizer (Quy tắc #48)
		log.Warn().Err(err).Str("url", sanitizeForLog(req.URL)).Msg("mixedcontent scan error")

		// 3. Phân loại lỗi HTTP chuyên sâu (Quy tắc #42) - Tránh shadowing interface (Quy tắc #47)
		status := resolveHTTPStatus(err, ctx.Err())

		// 4. Trả về lỗi dịch Tiếng Việt (Quy tắc #35)
		responseAPI.Error(c, status, errutil.TranslateError(err))
		return
	}

	// Trả về response chuẩn có kèm Meta
	responseAPI.Success(c, data, isCached, fetchedAt)
}

// sanitizeForLog cắt tỉa và loại bỏ ký tự điều khiển để chống Log Injection (Quy tắc #40)
func sanitizeForLog(u string) string {
	if len(u) > 500 {
		u = u[:500] + "..."
	}
	return logSanitizer.Replace(u)
}

// resolveHTTPStatus phân loại mã lỗi dựa trên ngữ cảnh và loại lỗi (Quy tắc #42)
func resolveHTTPStatus(err error, ctxErr error) int {
	// Ưu tiên check lỗi timeout từ context
	if ctxErr != nil {
		return http.StatusGatewayTimeout
	}

	// Check lỗi sentinel cho Rate Limit (Quy tắc #45)
	if errors.Is(err, service.ErrRateLimited) {
		return http.StatusTooManyRequests
	}

	// Check lỗi network type-safe.
	// net.DNSError cũng implement net.Error nên sẽ match ở đây (Quy tắc #47).
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return http.StatusGatewayTimeout
		}
		return http.StatusBadGateway
	}

	// Check lỗi từ Upstream (ví dụ: target server sập, 404, 500)
	var upstreamErr *service.UpstreamError
	if errors.As(err, &upstreamErr) {
		return http.StatusBadGateway
	}

	// Fallback cho các lỗi input hoặc SSRF (400)
	return http.StatusBadRequest
}
