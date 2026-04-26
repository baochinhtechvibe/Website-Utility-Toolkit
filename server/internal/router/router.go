package router

import (
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/middleware"
	botsimulator "tools.bctechvibe.com/server/internal/modules/bot-simulator"
	brokenlinkscanner "tools.bctechvibe.com/server/internal/modules/broken-link-scanner"
	"tools.bctechvibe.com/server/internal/modules/dns"
	imapmigrator "tools.bctechvibe.com/server/internal/modules/imap-migrator"
	iplookup "tools.bctechvibe.com/server/internal/modules/ip-lookup"
	jsontools "tools.bctechvibe.com/server/internal/modules/json-tools"
	mixedcontent "tools.bctechvibe.com/server/internal/modules/mixed-content"
	redirectchecker "tools.bctechvibe.com/server/internal/modules/redirect-checker"
	securityheaders "tools.bctechvibe.com/server/internal/modules/security-headers"
	"tools.bctechvibe.com/server/internal/modules/ssl"
	"tools.bctechvibe.com/server/internal/modules/visits"
	weblatency "tools.bctechvibe.com/server/internal/modules/web-latency"
	"tools.bctechvibe.com/server/internal/modules/whois"
)


func SetupRouter() *gin.Engine {
	// Disable Gin's default logger and recovery because we're managing them with zerolog and custom recovery
	r := gin.New()

	if trustedProxies := os.Getenv("TRUSTED_PROXIES"); trustedProxies != "" {
		proxies := strings.Split(trustedProxies, ",")
		for i, p := range proxies {
			proxies[i] = strings.TrimSpace(p)
		}
		if err := r.SetTrustedProxies(proxies); err != nil {
			panic("Failed to set trusted proxies: " + err.Error())
		}
	} else {
		// Trust no proxy by default to prevent IP spoofing
		r.SetTrustedProxies(nil)
	}

	r.Use(middleware.LoggerMiddleware())
	r.Use(middleware.RecoveryMiddleware())
	r.Use(middleware.CORSMiddleware())
	
	api := r.Group("/api")

	// Global Rate limit: 5 requests per second per IP across the standard API
	standardApi := api.Group("")
	standardApi.Use(middleware.RateLimitMiddleware(5))
	{
		dns.RegisterRoutes(standardApi)
		iplookup.RegisterRoutes(standardApi)
		mixedcontent.RegisterRoutes(standardApi)
		redirectchecker.RegisterRoutes(standardApi)
		visits.RegisterRoutes(standardApi)
		ssl.RegisterRoutes(standardApi)
		botsimulator.RegisterRoutes(standardApi)
		securityheaders.RegisterRoutes(standardApi)
		weblatency.RegisterRoutes(standardApi)
		jsontools.RegisterRoutes(standardApi)
		whois.RegisterRoutes(standardApi)
	}

	// IMAP Migrator handles its own rate limits internally
	imapmigrator.RegisterRoutes(api)

	// Broken Link Scanner is purely heavy, distinct limiting: 10/min + 1 InFlight + 8 Semaphore
	heavyApi := api.Group("")
	heavyApi.Use(middleware.RateLimitMiddlewareWithBurst(10.0/60.0, 5)) // 10 per minute, burst of 5
	heavyApi.Use(middleware.InFlightLimiter(1))
	heavyApi.Use(middleware.GlobalSemaphore(8))
	{
		brokenlinkscanner.RegisterRoutes(heavyApi)
	}

	return r
}
