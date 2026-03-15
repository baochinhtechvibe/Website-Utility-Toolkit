package middleware

import (
	"github.com/didip/tollbooth/v7"
	"github.com/didip/tollbooth_gin"
	"github.com/gin-gonic/gin"
)

func RateLimitMiddleware(max float64) gin.HandlerFunc {
	lmt := tollbooth.NewLimiter(max, nil)
	lmt.SetIPLookups([]string{"X-Forwarded-For", "RemoteAddr", "X-Real-IP"})
	
	return tollbooth_gin.LimitHandler(lmt)
}
