package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/response"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

var domainRe = regexp.MustCompile(
	`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
)

// csrSemaphore giới hạn số lượng request sinh key RSA/ECDSA chạy song song toàn server.
// RSA 4096 là CPU-bound, cho phép tối đa 5 goroutine song song để tránh starve CPU.
var csrSemaphore = make(chan struct{}, 5)

func normalizeIDN(host string) string {
	// Bỏ prefix wildcard trước khi normalize
	prefix := ""
	if strings.HasPrefix(host, "*.") {
		prefix = "*."
		host = host[2:]
	}
	// Thử chuyển Unicode domain → Punycode (idna.Lookup)
	if ascii, err := idna.Lookup.ToASCII(host); err == nil {
		return prefix + ascii
	}
	return prefix + host
}

func isValidCN(cn string) bool {
	if cn == "localhost" {
		return true
	}
	if net.ParseIP(cn) != nil {
		return true
	}
	normalized := normalizeIDN(cn)
	return domainRe.MatchString(normalized)
}

// GeneratorHandler đại diện cho bộ Router Handler của mô hình CSR Generator
type GeneratorHandler struct {
	svc      service.GeneratorService
	validate *validator.Validate
}

func NewGeneratorHandler(svc service.GeneratorService) *GeneratorHandler {
	return &GeneratorHandler{
		svc:      svc,
		validate: validator.New(),
	}
}

// GenerateCSR xử lý luồng yêu cầu JSON khởi lặp từ Client
func (h *GeneratorHandler) GenerateCSR(c *gin.Context) {
	// Giới hạn body trước khi bind — tránh memory pressure từ request lớn
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024) // 64KB

	var req models.GenerateCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// Trim server-side tất cả subject fields để tránh nhồi khoảng trắng
	req.DomainName = strings.TrimSpace(req.DomainName)
	req.State = strings.TrimSpace(req.State)
	req.Locality = strings.TrimSpace(req.Locality)
	req.Organization = strings.TrimSpace(req.Organization)
	req.OrganizationalUnit = strings.TrimSpace(req.OrganizationalUnit)
	req.Country = strings.TrimSpace(req.Country)

	// Normalize IDN → Punycode trước khi validate
	req.DomainName = normalizeIDN(req.DomainName)

	// Validate Struct Fields bắt buộc của Interface
	if err := h.validate.Struct(req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu cấu hình không hợp chuẩn (Kiểm tra lại độ dài và định dạng các trường)")
		return
	}

	// Validate Manual các trường kích cỡ Khóa (Bảo mật Server-side Security)
	if req.KeyType == "rsa" {
		if req.KeySize != 2048 && req.KeySize != 4096 {
			response.Error(c, http.StatusBadRequest, "Hệ thống chỉ cung cấp kích thước khóa RSA là 2048 hoặc 4096-bit")
			return
		}
	} else if req.KeyType == "ecdsa" {
		if req.KeySize != 256 && req.KeySize != 384 && req.KeySize != 521 {
			response.Error(c, http.StatusBadRequest, "Hệ thống chỉ cung cấp kích thước khóa ECDSA là P-256, P-384 hoặc P-521")
			return
		}
	}

	// Validate Regex Domain Name (CN) — sau IDN normalize
	if !isValidCN(req.DomainName) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền (Common Name) không hợp lệ")
		return
	}

	// Validate mảng SANs tối đa 100 Items
	var validSans []string
	for _, san := range req.Sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		// Normalize IDN cho từng SAN
		san = normalizeIDN(san)
		if !isValidCN(san) {
			response.Error(c, http.StatusBadRequest, "Danh sách SANs chứa Tên miền hoặc IP bị hỏng cấu trúc chuẩn")
			return
		}
		validSans = append(validSans, san)
	}
	if len(validSans) > 100 {
		response.Error(c, http.StatusBadRequest, "Chỉ cho phép khai báo tối đa 100 IP/Domain con (SANs)")
		return
	}
	req.Sans = validSans

	// Khởi tạo Context Timeout trước semaphore để deadline chạy ngay từ đây
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Semaphore: fail-fast nếu đang bận tối đa, trả 503 ngay lập tức không queue
	select {
	case csrSemaphore <- struct{}{}:
		defer func() { <-csrSemaphore }()
	default:
		response.Error(c, http.StatusServiceUnavailable, "Máy chủ đang bận sinh khóa, vui lòng thử lại sau")
		return
	}

	// Kích hoạt Core Logic x509 Module của Golang
	res, err := h.svc.GenerateCSR(ctx, &req)
	if err != nil {
		log.Error().Err(err).Msg("GenerateCSR Service x509 Error")

		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			response.Error(c, http.StatusGatewayTimeout, errutil.TranslateError(err))
			return
		}

		response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
		return
	}

	// [P1] Ngăn proxy/CDN/browser cache response chứa private key
	c.Header("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate")
	c.Header("Pragma", "no-cache")

	response.SuccessNoMeta(c, res)
}
