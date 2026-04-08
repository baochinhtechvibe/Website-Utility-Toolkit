package handlers

import (
	"net/http"

	"github.com/rs/zerolog/log"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/json-tools/models"
	"tools.bctechvibe.com/server/internal/modules/json-tools/service"
)

// MaxBodySizeMiddleware giới hạn kích thước request body (ví dụ: 1MB)
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
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ hoặc quá lớn. Vui lòng kiểm tra lại.",
		})
		return
	}

	result, err := service.JSONToGoStruct(req.JSON)
	if err != nil {
		// Log lỗi để debug
		log.Error().Err(err).Msg("[JSON-Tools] JSONToGoStruct Error")
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": models.ConvertResponse{
			Result: result,
		},
	})
}

// HandleJSONToYAML xử lý chuyển đổi JSON → YAML
func HandleJSONToYAML(c *gin.Context) {
	var req models.ConvertRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ hoặc quá lớn. Vui lòng kiểm tra lại.",
		})
		return
	}

	result, err := service.JSONToYAML(req.JSON)
	if err != nil {
		// Log lỗi để debug
		log.Error().Err(err).Msg("[JSON-Tools] JSONToYAML Error")
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": models.ConvertResponse{
			Result: result,
		},
	})
}
