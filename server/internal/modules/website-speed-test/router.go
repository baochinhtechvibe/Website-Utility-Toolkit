package websitespeedtest

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/website-speed-test/handlers"
)

func RegisterRoutes(r *gin.RouterGroup) {
	speedTest := r.Group("/website-speed-test")
	{
		speedTest.POST("/analyze", handlers.HandleAnalyze)
	}
}
