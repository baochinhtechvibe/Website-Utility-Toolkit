// ============================================
// FILE: cer-decoder/handlers/handler.go
//
// HTTP Handler cho CER Decoder (Gin framework)
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

	"tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/service"
)

type CERHandler struct {
	svc *service.Service
}

func NewCERHandler(svc *service.Service) *CERHandler {
	return &CERHandler{
		svc: svc,
	}
}

// HandleCerDecode xử lý POST /api/ssl/cer/decode
func (h *CERHandler) HandleCerDecode(c *gin.Context) {
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
	result, err := h.svc.Decode(ctx, req.CERT)
	if err != nil {
		// Hạ log level xuống Warn cho các lỗi input của người dùng
		if errors.Is(err, service.ErrCertTooLarge) ||
			errors.Is(err, service.ErrTrailingPEM) ||
			errors.Is(err, service.ErrInvalidPEM) ||
			errors.Is(err, service.ErrInvalidCER) {
			log.Warn().Err(err).Msg("Decode Certificate input error")
		} else {
			log.Error().Err(err).Msg("Decode Certificate internal error")
		}

		if errors.Is(err, context.DeadlineExceeded) {
			response.Error(c, http.StatusGatewayTimeout, "Xử lý yêu cầu quá hạn, vui lòng thử lại")
			return
		}

		if errors.Is(err, service.ErrCertTooLarge) {
			response.Error(c, http.StatusBadRequest, "Certificate vượt quá kích thước cho phép (tối đa 100KB)")
			return
		}

		if errors.Is(err, service.ErrTrailingPEM) {
			response.Error(c, http.StatusBadRequest, "Dữ liệu PEM chứa nội dung thừa sau Certificate (private key, v.v.)")
			return
		}

		if errors.Is(err, service.ErrInvalidPEM) {
			response.Error(c, http.StatusBadRequest, "Dữ liệu PEM không hợp lệ hoặc sai định dạng")
			return
		}

		if errors.Is(err, service.ErrInvalidCER) {
			response.Error(c, http.StatusBadRequest, "Certificate không thể giải mã")
			return
		}

		response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
		return
	}

	// 4. Response
	response.SuccessNoMeta(c, result)
}
