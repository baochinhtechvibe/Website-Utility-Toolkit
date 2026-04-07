package security_headers

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/security-headers/handlers"
)

func RegisterRoutes(router *gin.RouterGroup) {
	group := router.Group("/security-headers")
	{
		group.POST("/analyze", handlers.HandleAnalyze)
	}
}
