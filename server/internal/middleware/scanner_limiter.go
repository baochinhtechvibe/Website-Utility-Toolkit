package middleware

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/response"
)

// InFlightLimiter giới hạn số lượng request đang xử lý đồng thời theo từng IP.
// Phù hợp cho các tool nặng (scan, crawl) để tránh 1 IP độc chiếm tài nguyên.
func InFlightLimiter(maxConcurrent int) gin.HandlerFunc {
	var mu sync.Mutex
	inFlight := make(map[string]int)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		mu.Lock()
		count := inFlight[ip]
		if count >= maxConcurrent {
			mu.Unlock()
			response.Error(c, http.StatusTooManyRequests, "Bạn đang có quá nhiều tác vụ quét đồng thời. Vui lòng đợi tác vụ hiện tại hoàn thành rồi thử lại.")
			c.Abort()
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

// GlobalSemaphore giới hạn tổng số request đang xử lý trên toàn server.
// Phù hợp làm circuit breaker khi tải đột biến, tránh server bị OOM.
func GlobalSemaphore(maxConcurrent int) gin.HandlerFunc {
	sem := make(chan struct{}, maxConcurrent)

	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			// Lấy được slot, cho phép tiếp tục
			defer func() { <-sem }()
			c.Next()
		default:
			// Hết slot — server đang quá tải
			response.Error(c, http.StatusServiceUnavailable, "Hệ thống đang xử lý quá nhiều tác vụ cùng lúc. Vui lòng thử lại sau giây lát.")
			c.Abort()
		}
	}
}
