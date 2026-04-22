package handlers

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/models"
	"tools.bctechvibe.com/server/internal/modules/redirect-checker/service"
	"tools.bctechvibe.com/server/internal/platform/cache"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	"tools.bctechvibe.com/server/internal/platform/validator"
	responseAPI "tools.bctechvibe.com/server/internal/response"
)

type cachedRedirect struct {
	Data      models.RedirectAnalyzeData `json:"data"`
	FetchedAt time.Time                  `json:"fetched_at"`
}

var redirectCache = cache.New[string, cachedRedirect](5000, 15*time.Minute)

// HandleAnalyze processes the incoming request to analyze URL redirects.
func HandleAnalyze(c *gin.Context) {
	var req models.RedirectAnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		responseAPI.Error(c, http.StatusBadRequest, "Dữ liệu yêu cầu không hợp lệ")
		return
	}

	// 1. URL Length Validation
	if len(req.URL) > 2048 {
		responseAPI.Error(c, http.StatusBadRequest, "URL quá dài (vượt quá 2048 ký tự)")
		return
	}

	// Sanitize URL for parsing and logging
	targetURL := strings.TrimSpace(req.URL)
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Hostname() == "" {
		responseAPI.Error(c, http.StatusBadRequest, "URL không hợp lệ. Vui lòng kiểm tra lại địa chỉ website.")
		return
	}

	// SSRF Protection
	if !validator.IsSafeHostname(parsedURL.Hostname()) {
		responseAPI.Error(c, http.StatusBadRequest, "Địa chỉ IP hoặc Tên miền thuộc mạng nội bộ, không được phép tra cứu!")
		return
	}

	// Point #1 (Round 4): Sanitize first, Truncate later to avoid orphaned control characters
	sanitizedURL := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' { return -1 }
		return r
	}, targetURL)

	logURLRunes := []rune(sanitizedURL)
	var logURL string
	if len(logURLRunes) > 256 {
		logURL = string(logURLRunes[:253]) + "..."
	} else {
		logURL = sanitizedURL
	}

	// 2. Secure Cache Key (using SHA256 to prevent injection via UserAgent)
	rawKey := fmt.Sprintf("%s|%s|%v|%v", strings.ToLower(targetURL), req.UserAgent, req.DeepScan, req.IgnoreTLSErrors)
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(rawKey)))

	bypassCache := c.Query("bypassCache") == "true"
	
	if bypassCache {
		// Rate limit for bypass cache
		if err := service.CheckRateLimit(c.ClientIP()); err != nil {
			responseAPI.Error(c, http.StatusTooManyRequests, errutil.TranslateError(err))
			return
		}
		// Point #2: We don't delete immediately. Let the new successful fetch overwrite it.
		// If fetch fails, we still have the old data in cache as a fallback.
	} else {
		if item, found := redirectCache.Get(cacheKey); found {
			log.Info().Str("url", logURL).Msg("Returning cached redirect analysis")
			responseAPI.Success(c, item.Data, true, item.FetchedAt)
			return
		}
	}

	// Audit Logging
	log.Info().
		Str("url", logURL).
		Bool("deepScan", req.DeepScan).
		Bool("ignoreTLS", req.IgnoreTLSErrors).
		Str("ip", c.ClientIP()).
		Msg("Starting redirect analysis")

	resp, err := service.AnalyzeRedirects(c.Request.Context(), req)
	if err != nil {
		status := service.ResolveHTTPStatus(err, c.Request.Context().Err())
		log.Error().Err(err).Str("url", logURL).Int("status", status).Msg("Failed to analyze redirects")
		responseAPI.Error(c, status, errutil.TranslateError(err))
		return
	}

	// Cache the successful result
	redirectCache.Set(cacheKey, cachedRedirect{
		Data:      resp.Data,
		FetchedAt: time.Now(),
	}, 0)

	responseAPI.Success(c, resp.Data, false, time.Now())
}
