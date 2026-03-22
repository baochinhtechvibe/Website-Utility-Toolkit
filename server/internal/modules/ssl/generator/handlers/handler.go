package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"regexp"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
	"tools.bctechvibe.com/server/internal/response"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
)

var domainRe = regexp.MustCompile(
	`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`,
)

func isValidCN(cn string) bool {
	if cn == "localhost" {
		return true
	}
	if net.ParseIP(cn) != nil {
		return true
	}
	return domainRe.MatchString(cn)
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
	var req models.GenerateCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// Validate Struct Fields bắt buộc của Interface
	if err := h.validate.Struct(req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu cấu hình không hợp chuẩn (Bắt buộc phải có Tên miền, Key Type và Size)")
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

	// Validate Regex Regex Domain Name (CN)
	if !isValidCN(req.DomainName) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền (Common Name) không hợp lệ")
		return
	}

	// Validate mảng SANs tối đa 100 Items
	var validSans []string
	for _, san := range req.Sans {
		if san != "" {
			if !isValidCN(san) {
				response.Error(c, http.StatusBadRequest, "Danh sách SANs chứa Tên miền hoặc IP bị hỏng cấu trúc chuẩn")
				return
			}
			validSans = append(validSans, san)
		}
	}
	if len(validSans) > 100 {
		response.Error(c, http.StatusBadRequest, "Chỉ cho phép khai báo tối đa 100 IP/Domain con (SANs)")
		return
	}
	req.Sans = validSans

	// Khởi tạo Context Timeout cho phép gen 30 giây phục vụ Thread Block API đối với các server yếu (Core i3 không kéo nổi file 4096 liên tục)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Kích hoạt Core Logic x509 Module của Golang (No OpenSSL, No Exec, Memory-based, Native C Code speed)
	res, err := h.svc.GenerateCSR(ctx, &req)
	if err != nil {
		log.Error().Err(err).Msg("GenerateCSR Service x509 Error")

		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			response.Error(c, http.StatusGatewayTimeout, "Tiến trình chạy nền quá tải hoặc bị hủy (Timeout 30s).")
			return
		}

		response.Error(c, http.StatusInternalServerError, "Đóng gói mã RSA/ECDSA thất bại ở máy chủ, vui lòng quay lại sau.")
		return
	}

	response.SuccessNoMeta(c, res)
}
