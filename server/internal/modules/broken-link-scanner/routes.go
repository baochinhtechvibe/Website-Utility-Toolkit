package brokenlinkscanner

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/handlers"
)

// RegisterRoutes registers the specific heavy routes for the link scanner map.
func RegisterRoutes(r *gin.RouterGroup) {
	group := r.Group("/broken-link-scanner")
	{
		// Legacy synchronous endpoint (kept for backward compat)
		group.POST("/scan", handlers.HandleScan)
		// Async: submit job, get job_id immediately
		group.POST("/scan/submit", handlers.HandleSubmit)
		// Async: SSE stream — starts the job and streams progress + final result
		group.GET("/scan/status", handlers.HandleStatus)
		// Async: Explicitly cancel a running job
		group.POST("/scan/cancel", handlers.HandleCancel)
	}
}
