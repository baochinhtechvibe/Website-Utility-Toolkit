package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/models"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

var redirectCache = cache.NewMemoryCache(15 * time.Minute)

// HandleAnalyze processes the incoming request to analyze URL redirects.
func HandleAnalyze(c *gin.Context) {
	var req models.RedirectAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Error().Err(err).Msg("Invalid redirect analyze request payload")
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// Sanitize URL for logging to prevent log injection
	logURL := req.URL
	if len(logURL) > 256 {
		logURL = logURL[:253] + "..."
	}
	logURL = strings.ReplaceAll(logURL, "\n", "")
	logURL = strings.ReplaceAll(logURL, "\r", "")

	// Cache key: combination of URL, UA, and DeepScan setting
	// We don't use BypassCache in the request struct yet, but we'll check it from query/header if needed
	bypassCache := c.Query("bypassCache") == "true"
	cacheKey := strings.ToLower(req.URL) + "|" + req.UserAgent + "|" + strings.Join([]string{req.URL}, "")
	
	if !bypassCache {
		if cachedData, fetchedAt, found := redirectCache.Get(cacheKey); found {
			log.Info().Str("url", logURL).Msg("Returning cached redirect analysis")
			responseAPI.Success(c, cachedData, true, fetchedAt)
			return
		}
	}

	log.Info().Str("url", logURL).Msg("Starting redirect analysis")

	resp, err := service.AnalyzeRedirects(c.Request.Context(), req)
	if err != nil {
		log.Error().Err(err).Str("url", logURL).Msg("Failed to analyze redirects")
		responseAPI.Error(c, http.StatusInternalServerError, "Không thể phân tích chuyển hướng. Vui lòng kiểm tra lại URL hoặc thử lại sau.")
		return
	}

	// Cache the successful result
	redirectCache.Set(cacheKey, resp.Data)

	responseAPI.Success(c, resp.Data, false, time.Now())
}
