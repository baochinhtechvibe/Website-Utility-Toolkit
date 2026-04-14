package whois

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/middleware"
	"tools.bctechvibe.com/server/internal/modules/whois/handlers"
)

// RegisterRoutes đăng ký các route WHOIS vào router group
func RegisterRoutes(api *gin.RouterGroup) {
	whoisGroup := api.Group("/whois")
	// Giới hạn 20 requests/phút mỗi IP (≈ 0.33 req/s) để tránh bị WHOIS server chặn
	whoisGroup.Use(middleware.RateLimitMiddlewareWithBurst(20.0/60.0, 5))
	{
		whoisGroup.GET("/lookup", handlers.HandleWhoisLookup)
	}
}
