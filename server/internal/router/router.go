package router

import (
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/middleware"
	"tools.bctechvibe.com/server/internal/modules/dns"
	"tools.bctechvibe.com/server/internal/modules/ip"
	"tools.bctechvibe.com/server/internal/modules/redirect"
	"tools.bctechvibe.com/server/internal/modules/ssl"
	"tools.bctechvibe.com/server/internal/modules/visits"
)

func SetupRouter() *gin.Engine {
	// Disable Gin's default logger and recovery because we're managing them with zerolog and custom recovery
	r := gin.New()

	r.Use(middleware.LoggerMiddleware())
	r.Use(middleware.RecoveryMiddleware())
	r.Use(middleware.CORSMiddleware())
	
	// Global Rate limit: 5 requests per second per IP across the whole API
	r.Use(middleware.RateLimitMiddleware(5))

	api := r.Group("/api")
	{
		dns.RegisterRoutes(api)
		ip.RegisterRoutes(api)
		redirect.RegisterRoutes(api)
		visits.RegisterRoutes(api)
		ssl.RegisterRoutes(api)
	}

	return r
}

