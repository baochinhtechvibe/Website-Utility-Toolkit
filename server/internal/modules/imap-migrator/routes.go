package imapmigrator

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/middleware"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/handlers"
)

func RegisterRoutes(rg *gin.RouterGroup) {
	group := rg.Group("/imap-migrator")
	
	standardLimit := middleware.RateLimitMiddleware(5)
	permissiveLimit := middleware.RateLimitMiddleware(20)

	group.POST("/test-connection", standardLimit, handlers.HandleTestConnection)
	group.POST("/list-folders", standardLimit, handlers.HandleListFolders)
	group.POST("/start", standardLimit, handlers.HandleStart)
	group.POST("/cancel", standardLimit, handlers.HandleCancel)
	
	group.GET("/status", permissiveLimit, handlers.HandleStatus)
	group.GET("/stream", permissiveLimit, handlers.HandleStream)
}
