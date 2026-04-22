package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/response"
)

// cachedIPInfo bọc dữ liệu IP kèm timestamp để quản lý cache (theo pattern DNS handler)
type cachedIPInfo struct {
	Data      interface{} `json:"data"`
	FetchedAt time.Time   `json:"fetched_at"`
}

var ipCache = cache.New[string, cachedIPInfo](5000, 30*time.Minute)

// HandleMyIP trả về thông tin IP đầy đủ của người đang truy cập
func HandleMyIP(c *gin.Context) {
	clientIP := c.ClientIP()
	
	// Fallback cho localhost để test VPN
	clientIP = service.ResolvePublicIP(clientIP)

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := "myip:" + clientIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if item, found := ipCache.Get(cacheKey); found {
			response.Success(c, item.Data, true, item.FetchedAt)
			return
		}
	}

	now := time.Now()
	// Gọi sang service layer để xử lý nghiệp vụ
	info := service.GetIPDetails(c.Request.Context(), clientIP, userAgent)

	ipCache.Set(cacheKey, cachedIPInfo{
		Data:      info,
		FetchedAt: now,
	}, 0) // 0 = default TTL

	response.Success(c, info, false, now)
}

// HandleCheckIP trả về IP thô của client — dùng cho Smart Watcher (nhẹ, nhanh)
func HandleCheckIP(c *gin.Context) {
	clientIP := c.ClientIP()
	
	// Fallback cho localhost để test VPN
	clientIP = service.ResolvePublicIP(clientIP)

	c.JSON(http.StatusOK, gin.H{
		"ip": clientIP,
	})
}
