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

	// 3. Validate domain format
	if !validator.IsValidDomain(domain) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền không hợp lệ")
		return
	}

	// 3.1 Chặn IP address — SSL Checker chỉ hỗ trợ domain
	if net.ParseIP(domain) != nil {
		response.Error(c, http.StatusBadRequest, "SSL Checker chỉ hỗ trợ tên miền, không hỗ trợ địa chỉ IP. Vui lòng nhập tên miền (ví dụ: google.com).")
		return
	}

	if !validator.IsSafeHostname(domain) {
		response.Error(c, http.StatusBadRequest, "Tên miền không được phép (Local/Internal). Vui lòng sử dụng tên miền Public.")
		return
	}

	// 4. Context timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	// 5. Scan
	result, err := service.Scan(ctx, domain)
	if err != nil {
		handleScanError(c, err, domain)
		return
	}

	// 6. Response thành công
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

	errStr := err.Error()

	// DNS resolution failed
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) || strings.Contains(errStr, "dns resolve failed") {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Tên miền %s chưa phân giải được IP. Kiểm tra bản ghi DNS (A/AAAA).", domain))
		return
	}

	// TLS handshake failed
	if strings.Contains(errStr, "tls dial failed") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "tls: ") {
		response.Error(c, http.StatusBadGateway,
			fmt.Sprintf("Không thể kết nối SSL tới %s. Server có thể chưa cài SSL hoặc port 443 bị chặn.", domain))
		return
	}

	// No certificates found
	if strings.Contains(errStr, "no certificates found") {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Không tìm thấy chứng chỉ SSL trên %s.", domain))
		return
	}

	// No valid IP
	if strings.Contains(errStr, "no valid ip") {
		response.Error(c, http.StatusUnprocessableEntity,
			fmt.Sprintf("Tên miền %s chưa phân giải được IP. Kiểm tra bản ghi DNS (A/AAAA).", domain))
		return
	}

	// Fallback generic
	response.Error(c, http.StatusInternalServerError,
		"Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau.")
}
