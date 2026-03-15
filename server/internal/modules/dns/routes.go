package dns

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/dns/handlers"
)

// RegisterRoutes hook the dns endpoints into the provided gin router group
func RegisterRoutes(api *gin.RouterGroup) {
	dnsGroup := api.Group("/dns")
	{
		dnsGroup.POST("/lookup", handlers.HandleDNSLookup)
		dnsGroup.GET("/blacklist-stream/:ip", handlers.HandleBlacklistStream)
	}
}
