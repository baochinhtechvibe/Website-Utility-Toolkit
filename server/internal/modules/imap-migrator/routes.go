package imapmigrator

import (
	"os"

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

	// Admin API Protected with Basic Auth
	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASS")
	
	// Nếu không có env var, set mặc định cực khó hoặc log cảnh báo (để tránh account rỗng "": "")
	if adminUser == "" || adminPass == "" {
		adminUser = "admin" 
		adminPass = "Chinh$000210" // Default fallback nếu sếp chưa set env
	}

	adminGroup := group.Group("/admin")
	adminGroup.Use(gin.BasicAuth(gin.Accounts{
		adminUser: adminPass,
	}))
	adminGroup.GET("/history", handlers.HandleAdminHistory)
	adminGroup.GET("/running", handlers.HandleAdminRunningJobs)
	adminGroup.GET("/logs", handlers.HandleAdminLogFile)
}
