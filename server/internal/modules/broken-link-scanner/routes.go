package brokenlinkscanner

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/handlers"
)

// RegisterRoutes registers the specific heavy routes for the link scanner map.
func RegisterRoutes(r *gin.RouterGroup) {
	group := r.Group("/broken-link-scanner")
	{
		group.POST("/scan", handlers.HandleScan)
	}
}
