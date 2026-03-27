package middleware

import (
	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
)

func RateLimitMiddleware(max float64) gin.HandlerFunc {
	lmt := tollbooth.NewLimiter(max, nil)
	
	return func(c *gin.Context) {
		httpError := tollbooth.LimitByKeys(lmt, []string{c.ClientIP()})
		if httpError != nil {
			c.AbortWithStatusJSON(httpError.StatusCode, gin.H{
				"success": false,
				"error": httpError.Message,
			})
			return
		}
		c.Next()
	}
}
