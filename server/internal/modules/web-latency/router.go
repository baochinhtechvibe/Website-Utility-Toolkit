package weblatency

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/web-latency/handlers"
)

func RegisterRoutes(r *gin.RouterGroup) {
	webLatencyGroup := r.Group("/web-latency")
	{
		webLatencyGroup.POST("", handlers.HandleWebLatency)
	}
}
