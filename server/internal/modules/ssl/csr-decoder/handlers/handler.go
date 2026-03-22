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
		log.Error().Err(err).Msg("Decode CSR error")

		if errors.Is(err, context.DeadlineExceeded) {
			response.Error(c, http.StatusGatewayTimeout, "Xử lý yêu cầu quá hạn, vui lòng thử lại")
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

		response.Error(c, http.StatusInternalServerError, "Lỗi máy chủ ("+err.Error()+")")
		return
	}

	// 4. Response
	response.SuccessNoMeta(c, result)
}
