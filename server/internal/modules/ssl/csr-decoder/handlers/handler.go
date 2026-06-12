// ============================================
// FILE: csr-decoder/handlers/handler.go
//
// HTTP Handler cho CSR Decoder (Gin framework)
// ============================================

package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	response "tools.bctechvibe.com/server/internal/response"

	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/service"
)

type CSRHandler struct {
	svc *service.Service
}

func NewCSRHandler(svc *service.Service) *CSRHandler {
	return &CSRHandler{
		svc: svc,
	}
}

// HandleCSRDecode xử lý POST /api/ssl/csr/decode
func (h *CSRHandler) HandleCSRDecode(c *gin.Context) {
	// Giới hạn body trước khi bind — tránh memory pressure từ request lớn
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 256*1024) // 256KB

	// 1. Bind JSON
	var req models.DecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// 2. Context timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// 3. Decode
	result, err := h.svc.Decode(ctx, req.CSR)
	if err != nil {
		// Hạ log level xuống Warn cho các lỗi input của người dùng
		if errors.Is(err, service.ErrCSRTooLarge) ||
			errors.Is(err, service.ErrTrailingPEM) ||
			errors.Is(err, service.ErrInvalidPEM) ||
			errors.Is(err, service.ErrInvalidCSR) {
			log.Warn().Err(err).Msg("Decode CSR input error")
		} else {
			log.Error().Err(err).Msg("Decode CSR internal error")
		}

		if errors.Is(err, context.DeadlineExceeded) {
			response.Error(c, http.StatusGatewayTimeout, "Xử lý yêu cầu quá hạn, vui lòng thử lại")
			return
		}

		// [P1] CSR quá lớn là lỗi input của user → 400, không phải 500
		if errors.Is(err, service.ErrCSRTooLarge) {
			response.Error(c, http.StatusBadRequest, "CSR vượt quá kích thước cho phép (tối đa 100KB)")
			return
		}

		// [P2] Trailing PEM data → 400
		if errors.Is(err, service.ErrTrailingPEM) {
			response.Error(c, http.StatusBadRequest, "Dữ liệu PEM chứa nội dung thừa sau CSR (private key, chứng chỉ khác...)")
			return
		}

		if errors.Is(err, service.ErrInvalidPEM) {
			response.Error(c, http.StatusBadRequest, "Dữ liệu PEM không hợp lệ hoặc sai định dạng")
			return
		}

		if errors.Is(err, service.ErrInvalidCSR) {
			response.Error(c, http.StatusBadRequest, "CSR không thể giải mã")
			return
		}

		response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
		return
	}

	// 4. Response
	response.SuccessNoMeta(c, result)
}
