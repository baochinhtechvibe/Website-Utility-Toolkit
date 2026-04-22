package middleware

import (
	"net/http"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/response"
)

// RateLimitMiddleware giới hạn tần suất request theo IP (request/giây).
func RateLimitMiddleware(max float64) gin.HandlerFunc {
	lmt := tollbooth.NewLimiter(max, nil)

	return func(c *gin.Context) {
		httpError := tollbooth.LimitByKeys(lmt, []string{c.ClientIP()})
		if httpError != nil {
			response.Error(c, http.StatusTooManyRequests, "Thao tác quá nhanh, vui lòng chờ một chút rồi thử lại.")
			c.Abort()
			return
		}
		c.Next()
	}
}

// RateLimitMiddlewareWithBurst giới hạn tần suất request theo IP với burst size tùy chỉnh.
func RateLimitMiddlewareWithBurst(max float64, burst int) gin.HandlerFunc {
	lmt := tollbooth.NewLimiter(max, nil)
	lmt.SetBurst(burst)

	return func(c *gin.Context) {
		httpError := tollbooth.LimitByKeys(lmt, []string{c.ClientIP()})
		if httpError != nil {
			response.Error(c, http.StatusTooManyRequests, "Thao tác quá nhanh, vui lòng chờ một chút rồi thử lại.")
			c.Abort()
			return
		}
		c.Next()
	}
}
