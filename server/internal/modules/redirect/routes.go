package redirect

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/redirect/handlers"
)

// RegisterRoutes hook the redirect endpoints into the provided gin router group
func RegisterRoutes(api *gin.RouterGroup) {
	redirectGroup := api.Group("/redirect")
	{
		redirectGroup.POST("/analyze", handlers.HandleAnalyze)
	}
}
