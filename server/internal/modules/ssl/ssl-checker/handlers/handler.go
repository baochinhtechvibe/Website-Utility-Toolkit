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
	"tools.bctechvibe.com/server/pkg/validator"
)

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

	// 3. Validate domain format (IsValidDomain thường sẽ chặn IP và local hostname)
	if !validator.IsValidDomain(domain) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền không hợp lệ")
		return
	}

	// 3.1 Check Safe Hostname (Chặn private IP / Internal domain)
	if !validator.IsSafeHostname(domain) {
		response.Error(c, http.StatusBadRequest, "Tên miền không được phép (Local/Internal). Vui lòng sử dụng tên miền Public.")
		return
	}

	// 4. Context timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	// 5. Scan
	start := time.Now()
	result, err := service.Scan(ctx, domain)
	duration := time.Since(start)

	if err != nil {
		handleScanError(c, err, domain)
		return
	}

	// 6. Log success (Monitor)
	log.Info().Str("domain", domain).Dur("duration", duration).Msg("SSL check success")

	// 7. Response thành công
	response.SuccessNoMeta(c, result)
}

// ===========================
// Error classification
// ===========================

func handleScanError(c *gin.Context, err error, domain string) {

	// Timeout
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		response.Error(c, http.StatusGatewayTimeout,
			fmt.Sprintf("Quá thời gian chờ phản hồi từ %s. Vui lòng thử lại.", domain))
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
		response.Error(c, http.StatusBadGateway,
			fmt.Sprintf("Không thể thiết lập kết nối SSL bảo mật tới %s. Có thể server chưa cấu hình đúng TLS hoặc chứng chỉ không hợp lệ.", domain))
		return
	}

	// No certificates found
	if errors.Is(err, service.ErrNoCertificates) {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Không tìm thấy chứng chỉ SSL trên %s.", domain))
		return
	}

	// Fallback generic
	response.Error(c, http.StatusInternalServerError,
		"Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau.")
}
