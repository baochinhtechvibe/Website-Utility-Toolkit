package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/json-tools/models"
	"tools.bctechvibe.com/server/internal/modules/json-tools/service"
)

// HandleJSONToGoStruct xử lý chuyển đổi JSON → Go Struct
func HandleJSONToGoStruct(c *gin.Context) {
	var req models.ConvertRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ. Vui lòng kiểm tra lại.",
		})
		return
	}

	result, err := service.JSONToGoStruct(req.JSON)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
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
			"message": "Dữ liệu yêu cầu không hợp lệ. Vui lòng kiểm tra lại.",
		})
		return
	}

	result, err := service.JSONToYAML(req.JSON)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
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

// HandleJSONDiff xử lý so sánh 2 JSON
func HandleJSONDiff(c *gin.Context) {
	var req models.DiffRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ. Vui lòng gửi cả Original và Modified JSON.",
		})
		return
	}

	result, err := service.ComputeDiff(req.Original, req.Modified)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}
