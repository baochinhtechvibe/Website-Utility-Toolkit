package redirectchecker

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/handlers"
)

// RegisterRoutes hook the redirect endpoints into the provided gin router group
func RegisterRoutes(api *gin.RouterGroup) {
	redirectGroup := api.Group("/redirect-checker")
	{
		redirectGroup.POST("/analyze", handlers.HandleAnalyze)
	}
}
