package mixedcontent

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/handlers"
)

// RegisterRoutes hook mixed content endpoints vào router group
func RegisterRoutes(api *gin.RouterGroup) {
	mcGroup := api.Group("/mixed-content")
	{
		mcGroup.POST("/scan", handlers.HandleScan)
	}
}
