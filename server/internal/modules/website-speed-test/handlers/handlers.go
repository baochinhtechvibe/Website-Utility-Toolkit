package handlers

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/didip/tollbooth/v7"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/website-speed-test/models"
	"tools.bctechvibe.com/server/internal/modules/website-speed-test/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/validator"
	"tools.bctechvibe.com/server/internal/response"
)

type cachedResult struct {
	Data      *models.SpeedTestResult
	FetchedAt time.Time
}

var (
	speedTestCache = cache.New[string, cachedResult](100, 5*time.Minute)
	
	speedTestLimiter = tollbooth.NewLimiter(10.0/60.0, nil) // 10 per minute
	inFlight         = make(map[string]int)
	mu               sync.Mutex
	globalSem        = make(chan struct{}, 8)
)

func init() {
	speedTestLimiter.SetBurst(5)
}

func HandleAnalyze(c *gin.Context) {
	// Limit body to 64KB
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024)
	
	var req models.SpeedTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu đầu vào không hợp lệ hoặc quá lớn")
		return
	}

	// Normalize URL
	inputURL := strings.TrimSpace(req.URL)
	if !strings.HasPrefix(inputURL, "http://") && !strings.HasPrefix(inputURL, "https://") {
		inputURL = "https://" + inputURL
	}

	// Validate URL
	parsedURL, err := url.ParseRequestURI(inputURL)
	if err != nil || !validator.IsSafeHostname(parsedURL.Hostname()) {
		response.Error(c, http.StatusBadRequest, "URL không hợp lệ hoặc không an toàn")
		return
	}

	// Double-select pattern
	type analyzeResult struct {
		data *models.SpeedTestResult
		err  error
	}
	resChan := make(chan analyzeResult, 1)

	// Context for handler
	ctx, cancel := context.WithTimeout(c.Request.Context(), 45*time.Second)
	defer cancel()

	requestID := c.GetString("request_id")
	l := log.With().Str("request_id", requestID).Str("url", parsedURL.String()).Logger()

	rawKey := fmt.Sprintf("%s|v=1", parsedURL.String())
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(rawKey)))
	if !req.BypassCache {
		if cRes, ok := speedTestCache.Get(cacheKey); ok {
			l.Info().Msg("speed test returned from cache")
			response.Success(c, cRes.Data, true, cRes.FetchedAt)
			return
		}
	}

	// Not cached, apply heavy limits manually
	if httpError := tollbooth.LimitByKeys(speedTestLimiter, []string{c.ClientIP()}); httpError != nil {
		response.Error(c, http.StatusTooManyRequests, "Thao tác quá nhanh, vui lòng chờ một chút rồi thử lại.")
		return
	}

	mu.Lock()
	if inFlight[c.ClientIP()] >= 1 {
		mu.Unlock()
		response.Error(c, http.StatusTooManyRequests, "Bạn đang có quá nhiều tác vụ phân tích đồng thời. Vui lòng đợi tác vụ hiện tại hoàn thành rồi thử lại.")
		return
	}
	inFlight[c.ClientIP()]++
	mu.Unlock()

	defer func() {
		mu.Lock()
		inFlight[c.ClientIP()]--
		mu.Unlock()
	}()

	select {
	case globalSem <- struct{}{}:
		defer func() { <-globalSem }()
	default:
		response.Error(c, http.StatusServiceUnavailable, "Hệ thống đang xử lý quá nhiều tác vụ cùng lúc. Vui lòng thử lại sau giây lát.")
		return
	}

	l.Info().Msg("starting speed test")
	
	// Khởi chạy phân tích
	go func() {
		data, err := service.RunSpeedTest(ctx, parsedURL.String())
		resChan <- analyzeResult{data, err}
	}()

	handleResult := func(res analyzeResult) {
		if res.err != nil {
			l.Error().Err(res.err).Msg("speed test failed")
			if errors.Is(res.err, context.DeadlineExceeded) || strings.Contains(res.err.Error(), "timeout") {
				response.Error(c, http.StatusGatewayTimeout, "Quá trình phân tích mất quá nhiều thời gian. Vui lòng thử lại sau.")
				return
			}
			if strings.Contains(res.err.Error(), "executable file not found") {
				response.Error(c, http.StatusInternalServerError, "Hệ thống thiếu Chrome/Chromium để phân tích.")
				return
			}
			response.Error(c, http.StatusInternalServerError, "Không thể phân tích trang web này. Vui lòng thử lại sau.")
			return
		}
		l.Info().Msg("speed test success")
		speedTestCache.Set(cacheKey, cachedResult{Data: res.data, FetchedAt: time.Now()}, 5*time.Minute)
		response.Success(c, res.data, false, time.Now())
	}

	select {
	case res := <-resChan:
		handleResult(res)
		return
	default:
	}

	select {
	case <-ctx.Done():
		select {
		case res := <-resChan:
			handleResult(res)
			return
		default:
		}
		l.Warn().Msg("speed test timeout or cancelled")
		response.Error(c, http.StatusGatewayTimeout, "Quá thời gian phân tích, trang web phản hồi quá chậm")
		return
	case res := <-resChan:
		handleResult(res)
	}
}
