package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"tools.bctechvibe.com/server/internal/modules/json-tools/models"
	"tools.bctechvibe.com/server/internal/modules/json-tools/service"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

// MaxBodySizeMiddleware giới hạn kích thước request body
func MaxBodySizeMiddleware(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		c.Next()
	}
}

// HandleJSONToGoStruct xử lý chuyển đổi JSON → Go Struct
func HandleJSONToGoStruct(c *gin.Context) {
	var req models.ConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ hoặc quá lớn. Vui lòng kiểm tra lại.")
		return
	}

	result, err := service.JSONToGoStruct(req.JSON)
	if err != nil {
		log.Error().Err(err).Msg("[JSON-Tools] JSONToGoStruct Error")
		// Lỗi từ service JSON là user-facing (lỗi cú pháp JSON), an toàn để hiển thị
		responseAPI.Error(c, http.StatusUnprocessableEntity, err.Error())
		return
	}

	responseAPI.SuccessNoMeta(c, models.ConvertResponse{Result: result})
}

// HandleJSONToYAML xử lý chuyển đổi JSON → YAML
func HandleJSONToYAML(c *gin.Context) {
	var req models.ConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ hoặc quá lớn. Vui lòng kiểm tra lại.")
		return
	}

	result, err := service.JSONToYAML(req.JSON)
	if err != nil {
		log.Error().Err(err).Msg("[JSON-Tools] JSONToYAML Error")
		// Lỗi từ service JSON là user-facing (lỗi cú pháp JSON), an toàn để hiển thị
		responseAPI.Error(c, http.StatusUnprocessableEntity, err.Error())
		return
	}

	responseAPI.SuccessNoMeta(c, models.ConvertResponse{Result: result})
}
