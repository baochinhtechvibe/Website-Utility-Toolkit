package handlers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/response"
)

var blsCache = cache.NewMemoryCache(30 * time.Minute)

// HandleScan kicks off sync POST link checking mechanism.
func HandleScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu nhập vào chưa đúng định dạng. Vui lòng kiểm tra lại URL hoặc cấu hình.")
		return
	}

	// 1. URL Length Validation (GEMINI Rule #30)
	if len(req.URL) > 2048 {
		response.Error(c, http.StatusBadRequest, "URL quá dài (vượt quá 2048 ký tự)")
		return
	}

	// 2. Secure Cache Key using SHA256 (GEMINI Rule #30)
	// Bổ sung TLS config vào key để tránh cache pollution giữa các chế độ quét (Issue #2)
	rawKey := fmt.Sprintf("bls:%s:%s:tls=%v", strings.ToLower(req.URL), req.Scope, req.IgnoreTlsErrors)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(rawKey)))

	// 3. Cache Bypass Logic Fix (GEMINI Rule #11)
	if !req.BypassCache {
		if data, fetchedAt, found := blsCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	// Hard timeout execution limit
	ctx, cancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	defer cancel()

	// 4. Unicode-safe Log Sanitization (Di chuyển xuống sau Cache Check để tối ưu - Issue #4)
	cleanURL := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' { return -1 }
		return r
	}, req.URL)
	runes := []rune(cleanURL)
	var logURL string
	if len(runes) > 256 {
		logURL = string(runes[:253]) + "..."
	} else {
		logURL = cleanURL
	}

	// Run scanner service
	dataChan := make(chan models.ScanData, 1)
	errChan := make(chan error, 1)

	go func() {
		data, err := service.ProcessScan(ctx, req) 
		if err != nil {
			errChan <- err
			return
		}
		dataChan <- data
	}()

	// 5. Prioritize result channels over context done (Issue #1 - Double-select pattern)
	select {
	case err := <-errChan:
		log.Error().Err(err).Str("url", logURL).Str("request_id", c.GetString("requestID")).Msg("broken-link scan error")
		response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
		return
	case scanData := <-dataChan:
		blsCache.Set(cacheKey, scanData)
		response.Success(c, scanData, false, time.Now())
		return
	default:
		// No immediate result, wait with timeout
	}

	select {
	case <-ctx.Done():
		// Chỉ timeout nếu sau 35s vẫn chưa có kết quả trong dataChan/errChan
		response.Error(c, http.StatusGatewayTimeout, "Pha thực thi vượt quá giới hạn 35 giây do quá nhiều Links hoặc Server tải quá chậm.")
		return
	case err := <-errChan:
		log.Error().Err(err).Str("url", logURL).Str("request_id", c.GetString("requestID")).Msg("broken-link scan error")
		response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
		return
	case scanData := <-dataChan:
		blsCache.Set(cacheKey, scanData)
		response.Success(c, scanData, false, time.Now())
		return
	}
}
