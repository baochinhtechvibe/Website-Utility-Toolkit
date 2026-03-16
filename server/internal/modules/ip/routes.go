package ip

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip/handlers"
)

func RegisterRoutes(api *gin.RouterGroup) {
	ipGroup := api.Group("/ip")
	{
		ipGroup.GET("/my-ip", handlers.HandleMyIP)
		ipGroup.GET("/info/:ip", handlers.HandleIPLookup)
	}
}
