package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/models"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/service"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

// HandleScan xử lý POST /api/mixed-content/scan
func HandleScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ",
		})
		return
	}

	data, err, isCached, fetchedAt := service.ScanMixedContent(c.Request.Context(), req)
	if err != nil {
		log.Warn().Err(err).Str("url", req.URL).Msg("mixedcontent scan error")
		
		// Phân loại lỗi
		if c.Request.Context().Err() != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{
				"success": false,
				"message": "Timeout khi fetch URL. Vui lòng thử lại sau.",
			})
			return
		}

		// Dịch lỗi sang tiếng Việt an toàn, không lộ thông tin nội bộ
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": errutil.TranslateError(err),
		})
		return
	}

	// Trả về response chuẩn có kèm Meta
	responseAPI.Success(c, data, isCached, fetchedAt)
}
