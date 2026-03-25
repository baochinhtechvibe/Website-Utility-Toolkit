package botsimulator

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/bot-simulator/handlers"
)

// RegisterRoutes đăng ký các endpoint của bot-simulator vào api router group.
func RegisterRoutes(api *gin.RouterGroup) {
	group := api.Group("/bot-simulator")
	{
		group.POST("/analyze", handlers.HandleAnalyze)
	}
}
