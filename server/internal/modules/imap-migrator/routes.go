package imapmigrator

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
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
	group.GET("/my-jobs", permissiveLimit, handlers.HandleMyJobs)

	// Admin API Protected with Basic Auth
	// Nếu không có ADMIN_USER/ADMIN_PASS trong env → tắt hoàn toàn Admin API
	// (không boot với credential mặc định → an toàn hơn cho production)
	adminUser := os.Getenv("ADMIN_USER")
	adminPass := os.Getenv("ADMIN_PASS")

	if adminUser != "" && adminPass != "" {
		adminGroup := group.Group("/admin")
		adminGroup.Use(gin.BasicAuth(gin.Accounts{
			adminUser: adminPass,
		}))
		adminGroup.GET("/history", handlers.HandleAdminHistory)
		adminGroup.GET("/running", handlers.HandleAdminRunningJobs)
		adminGroup.GET("/logs", handlers.HandleAdminLogFile)
		log.Info().Msg("[IMAP Admin] Admin API đã được bật với user: " + adminUser)
	} else {
		// Warning rõ ràng khi khởi động → tránh debug mất thời gian khi test
		log.Warn().Msg("[IMAP Admin] ADMIN_USER hoặc ADMIN_PASS chưa được set trong env." +
			" Admin API đang bị tắt (404). Chạy lại server với ADMIN_USER=xxx ADMIN_PASS=yyy để bật.")
	}
}
