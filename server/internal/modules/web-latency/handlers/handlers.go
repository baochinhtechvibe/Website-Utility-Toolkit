package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/web-latency/models"
	"tools.bctechvibe.com/server/internal/modules/web-latency/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

var webLatencyCache = cache.NewMemoryCache(30 * time.Minute)

func HandleWebLatency(c *gin.Context) {
	var req models.WebLatencyRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Dữ liệu yêu cầu không hợp lệ",
		})
		return
	}

	req.URL = strings.TrimSpace(req.URL)
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "URL không được để trống",
		})
		return
	}

	// Validate basic url
	if !strings.HasPrefix(req.URL, "http://") && !strings.HasPrefix(req.URL, "https://") {
		req.URL = "https://" + req.URL
	}

	cacheKey := fmt.Sprintf("%s:%v", req.URL, req.DeepTest)
	if !req.BypassCache {
		if data, fetchedAt, found := webLatencyCache.Get(cacheKey); found {
			responseAPI.Success(c, data, true, fetchedAt)
			return
		}
	} else {
		webLatencyCache.Delete(cacheKey)
	}

	result, err := service.AnalyzeLatency(c.Request.Context(), req.URL, req.DeepTest)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "Lỗi khi kiểm tra tốc độ: " + err.Error(),
		})
		return
	}

	webLatencyCache.Set(cacheKey, result)
	responseAPI.Success(c, result, false, time.Now())
}
