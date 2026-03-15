package visits

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/visits/handlers"
)

func RegisterRoutes(router *gin.RouterGroup) {
	router.GET("/visits", handlers.GetStats)
	router.POST("/visits", handlers.TrackVisit)
}
