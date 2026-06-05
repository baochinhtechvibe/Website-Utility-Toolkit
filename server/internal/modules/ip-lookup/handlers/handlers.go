package handlers

import (
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
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

	// Fallback cho localhost để test VPN (Chỉ chạy ở Debug mode, tránh ghi đè ở Production proxy)
	if gin.Mode() == gin.DebugMode {
		clientIP = service.ResolvePublicIP(clientIP)
	} else {
		ip := net.ParseIP(clientIP)
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			response.Error(c, http.StatusInternalServerError, "Hệ thống phát hiện lỗi cấu hình TRUSTED_PROXIES (nhận được IP nội bộ từ Reverse Proxy).")
			return
		}
	}

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := "myip:" + clientIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if item, found := ipCache.Get(cacheKey); found {
			// Ép kiểu và clone data để thay đổi UA/Browser realtime mà không ảnh hưởng cache
			if cachedInfo, ok := item.Data.(*models.IPInfo); ok {
				info := *cachedInfo
				info.UserAgent = userAgent
				info.Browser, info.OS = service.ParseUserAgent(userAgent)
				response.Success(c, &info, true, item.FetchedAt)
				return
			}
		}
	}

	now := time.Now()
	// Gọi sang service layer để xử lý nghiệp vụ
	info := service.GetIPDetails(c.Request.Context(), clientIP, userAgent)

	// Clone một bản sạch (không UA/Browser) để cache dùng chung cho mọi user trùng IP
	cleanCacheInfo := *info
	cleanCacheInfo.UserAgent = ""
	cleanCacheInfo.Browser = ""
	cleanCacheInfo.OS = ""

	ipCache.Set(cacheKey, cachedIPInfo{
		Data:      &cleanCacheInfo,
		FetchedAt: now,
	}, 0) // 0 = default TTL

	response.Success(c, info, false, now)
}

// HandleCheckIP trả về IP thô của client — dùng cho Smart Watcher (nhẹ, nhanh)
func HandleCheckIP(c *gin.Context) {
	clientIP := c.ClientIP()

	// Fallback cho localhost để test VPN
	if gin.Mode() == gin.DebugMode {
		clientIP = service.ResolvePublicIP(clientIP)
	} else {
		ip := net.ParseIP(clientIP)
		if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			response.Error(c, http.StatusInternalServerError, "Hệ thống phát hiện lỗi cấu hình TRUSTED_PROXIES.")
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ip": clientIP,
	})
}
