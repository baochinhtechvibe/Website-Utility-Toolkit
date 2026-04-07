package handlers

import (
	"fmt"
	"net/http"
	"net/url"
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

	req.URL = normalizeURL(req.URL)
	if req.URL == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "URL không hợp lệ",
		})
		return
	}

	cacheKey := fmt.Sprintf("%s:deep=%v", req.URL, req.DeepTest)
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
		c.JSON(http.StatusBadGateway, gin.H{
			"success": false,
			"message": "Lỗi khi kiểm tra tốc độ: " + err.Error(),
		})
		return
	}

	webLatencyCache.Set(cacheKey, result)
	responseAPI.Success(c, result, false, time.Now())
}

func normalizeURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}

	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		u = "https://" + u
	}

	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return ""
	}

	// Chặn các scheme nguy hiểm như ftp://, javascript://, file://...
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}

	// RFC 3986: Scheme và Host là case-insensitive
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	
	// Normalize Path: Chỉ xóa trailing slash của root domain (/)
	// VD: https://example.com/ -> https://example.com
	// Nhưng https://example.com/blog/ -> https://example.com/blog/ (Giữ nguyên slash của path)
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	
	return parsed.String()
}
