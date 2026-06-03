// ============================================
// FILE: ssl-checker/handlers/handler.go
//
// HTTP Handler cho SSL Checker (Gin framework)
// Error codes chuẩn production:
//   400 - Request không hợp lệ
//   422 - DNS fail / Không có certificate
//   429 - Rate limit
//   500 - Lỗi hệ thống
//   502 - TLS handshake fail
//   504 - Timeout
// ============================================

package handlers

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	response "tools.bctechvibe.com/server/internal/response"

	"tools.bctechvibe.com/server/internal/modules/ssl/ssl-checker/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/ssl-checker/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

type cachedSSL struct {
	Data      *models.SSLCheckResponse `json:"data"`
	FetchedAt time.Time                `json:"fetched_at"`
}

var sslCache = cache.New[string, cachedSSL](5000, 30*time.Minute)

// ===========================
// Domain normalization
// ===========================

func normalizeHostname(input string) string {
	input = strings.TrimSpace(input)

	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		if u, err := url.Parse(input); err == nil && u.Host != "" {
			input = u.Host
		}
	}

	if host, _, err := net.SplitHostPort(input); err == nil {
		input = host
	}

	input = strings.TrimSuffix(input, "/")
	input = strings.TrimSuffix(input, ".")

	return input
}

// ===========================
// Main Handler
// ===========================

// HandleSSLCheck xử lý POST /api/ssl/check
func HandleSSLCheck(c *gin.Context) {

	// Giới hạn body trước khi bind — tránh memory pressure từ request lớn
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024) // 32KB

	// 1. Bind JSON
	var req models.CheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// 2. Normalize domain
	domain := normalizeHostname(req.Domain)

	if domain == "" {
		response.Error(c, http.StatusBadRequest, "Vui lòng nhập tên miền cần kiểm tra")
		return
	}

	// 3. Validate domain syntax
	if !validator.IsValidDomain(domain) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền không hợp lệ")
		return
	}

	// 3.5. Chặn các IP Private/Local để đảm bảo an toàn hệ thống (SSRF protection)
	if !validator.IsSafeHostname(domain) {
		response.Error(c, http.StatusBadRequest, "Địa chỉ IP hoặc Tên miền thuộc mạng nội bộ, không được phép tra cứu!")
		return
	}

	// 4. Cache interception
	cacheKey := "ssl:" + domain
	if !req.BypassCache {
		if item, found := sslCache.Get(cacheKey); found {
			response.Success(c, item.Data, true, item.FetchedAt)
			return
		}
	} else {
		sslCache.Delete(cacheKey)
	}

	// 5. Context timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	// 6. Scan
	start := time.Now()
	result, err := service.Scan(ctx, domain)
	duration := time.Since(start)

	if err != nil {
		handleScanError(c, err, domain)
		return
	}

	// 7. Update cache & Log success
	sslCache.Set(cacheKey, cachedSSL{
		Data:      result,
		FetchedAt: time.Now(),
	}, 0)

	if result.HandshakeError != "" {
		log.Warn().Str("domain", domain).Str("error", result.HandshakeError).Msg("SSL handshake failed (Partial Result)")
	} else {
		log.Info().Str("domain", domain).Dur("duration", duration).Msg("SSL check success")
	}

	// 8. Response thành công (ngay cả khi handshake_error có dữ liệu, vì ta vẫn có IP/ServerType)
	response.Success(c, result, false, time.Now())
}

// ===========================
// Error classification
// ===========================

func handleScanError(c *gin.Context, err error, domain string) {

	// Timeout
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		response.Error(c, http.StatusGatewayTimeout, errutil.TranslateError(err))
		return
	}

	// DNS resolution failed
	if errors.Is(err, service.ErrDNSFailed) || errors.Is(err, service.ErrNoIP) {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Tên miền %s chưa phân giải được IP. Kiểm tra bản ghi DNS (A/AAAA).", domain))
		return
	}

	// TLS handshake failed
	if errors.Is(err, service.ErrTLSFailed) {
		log.Error().Err(err).Str("domain", domain).Msg("TLS handshake failed")

		msg := fmt.Sprintf("Không tìm thấy chứng chỉ SSL hoặc không thể thiết lập kết nối an toàn tới %s. Vui lòng đảm bảo tên miền đã trỏ đúng IP máy chủ và cổng SSL (mặc định là 443) đang mở.", domain)
		response.Error(c, http.StatusBadGateway, msg)
		return
	}

	// No certificates found
	if errors.Is(err, service.ErrNoCertificates) {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Không tìm thấy chứng chỉ SSL trên %s.", domain))
		return
	}

	// Fallback generic
	log.Error().Err(err).Str("domain", domain).Msg("SSL check unexpected error")
	response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
}
