package whois

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/whois/handlers"
)

// RegisterRoutes đăng ký các route WHOIS vào router group
func RegisterRoutes(api *gin.RouterGroup) {
	whoisGroup := api.Group("/whois")
	{
		whoisGroup.GET("/lookup", handlers.HandleWhoisLookup)
	}
}
