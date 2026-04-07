package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
)

// InFlightLimiter limits the number of concurrent requests per IP
func InFlightLimiter(maxConcurrent int) gin.HandlerFunc {
	var mu sync.Mutex
	inFlight := make(map[string]int)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		count := inFlight[ip]
		if count >= maxConcurrent {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"success": false,
				"error":   "Bạn đã đạt giới hạn luồng quét đồng thời.",
			})
			return
		}
		inFlight[ip] = count + 1
		mu.Unlock()

		defer func() {
			mu.Lock()
			inFlight[ip]--
			if inFlight[ip] == 0 {
				delete(inFlight, ip)
			}
			mu.Unlock()
		}()

		c.Next()
	}
}

// GlobalSemaphore limits the total number of concurrent requests globally
func GlobalSemaphore(maxConcurrent int) gin.HandlerFunc {
	sem := make(chan struct{}, maxConcurrent)

	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			// Acquired lock
			defer func() { <-sem }()
			c.Next()
		default:
			// Full
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"error":   "Hệ thống đang quá tải luồng phân tích. Vui lòng thử lại sau giây lát.",
			})
			return
		}
	}
}
