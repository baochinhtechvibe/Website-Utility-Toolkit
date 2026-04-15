package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/response"
)

var ipCache = cache.NewMemoryCache(30 * time.Minute)

// HandleMyIP trả về thông tin IP của người đang truy cập
func HandleMyIP(c *gin.Context) {
	clientIP := c.ClientIP()

	// Logic lấy IP thực tế khi chạy ở local hoặc qua proxy
	// (Giữ nguyên logic clientIP từ gin-gonic/gin vì nó đã handle X-Forwarded-For)

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := "myip:" + clientIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if data, fetchedAt, found := ipCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	now := time.Now()
	// Gọi sang service layer để xử lý nghiệp vụ
	info := service.GetIPDetails(c.Request.Context(), clientIP, userAgent)

	ipCache.Set(cacheKey, info)
	response.Success(c, info, false, now)
}
