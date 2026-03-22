// ============================================
// FILE: key-matcher/handlers/handler.go
//
// HTTP Handler cho SSL Key Matcher (Refactored)
// ============================================

package handlers

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/service"
	response "tools.bctechvibe.com/server/internal/response"
)

var validMatchTypes = map[string]bool{
	"cert_key": true,
	"csr_cert": true,
}

type KeyMatchHandler struct {
	svc *service.Service
}

func NewKeyMatchHandler(svc *service.Service) *KeyMatchHandler {
	return &KeyMatchHandler{svc: svc}
}

func (h *KeyMatchHandler) HandleKeyMatch(c *gin.Context) {
	var req models.MatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// Validate type field — service không tự reject được
	if !validMatchTypes[req.Type] {
		response.Error(c, http.StatusBadRequest, "Loại đối soát không hợp lệ (chỉ chấp nhận: cert_key, csr_cert)")
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	res, err := h.svc.Match(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			response.Error(c, http.StatusGatewayTimeout, "Quá thời gian xử lý, vui lòng thử lại")
			return
		}
		log.Error().Err(err).Str("type", req.Type).Msg("Key match failed")
		response.Error(c, http.StatusInternalServerError, "Lỗi hệ thống trong quá trình đối soát")
		return
	}

	log.Info().Str("type", req.Type).Bool("matched", res.Matched).Msg("Key match completed")
	c.JSON(http.StatusOK, res)
}
