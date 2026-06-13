package handlers

import (
	"context"
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
	// Limit request body size to prevent memory abuse from oversized payloads
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)

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

	// Normalize bare domain (e.g. "google.com") → "https://google.com"
	// Frontend already does this, but backend must also handle direct API calls
	if !strings.Contains(targetURL, "://") {
		targetURL = "https://" + targetURL
	}

	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Hostname() == "" {
		responseAPI.Error(c, http.StatusBadRequest, "URL không hợp lệ. Vui lòng kiểm tra lại địa chỉ website.")
		return
	}

	// Restrict scheme to http/https only — reject ftp://, file://, etc.
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		responseAPI.Error(c, http.StatusBadRequest, "Chỉ hỗ trợ URL có giao thức HTTP hoặc HTTPS")
		return
	}

	// SSRF Protection
	if !validator.IsSafeHostname(parsedURL.Hostname()) {
		responseAPI.Error(c, http.StatusBadRequest, "Địa chỉ IP hoặc Tên miền thuộc mạng nội bộ, không được phép tra cứu!")
		return
	}

	// Sync normalized URL back to request so service receives the full URL
	req.URL = targetURL

	// Point #1 (Round 4): Sanitize first, Truncate later to avoid orphaned control characters
	sanitizedURL := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, targetURL)

	logURLRunes := []rune(sanitizedURL)
	var logURL string
	if len(logURLRunes) > 256 {
		logURL = string(logURLRunes[:253]) + "..."
	} else {
		logURL = sanitizedURL
	}

	// Normalize only Scheme and Host for case-insensitivity, keep Path/Query intact
	normalizedHostURL := fmt.Sprintf("%s://%s%s",
		strings.ToLower(parsedURL.Scheme),
		strings.ToLower(parsedURL.Host),
		parsedURL.RequestURI(),
	)

	// 2. Secure Cache Key (using SHA256 to prevent injection via UserAgent)
	rawKey := fmt.Sprintf("%s|%s|%v|%v", normalizedHostURL, req.UserAgent, req.DeepScan, req.IgnoreTLSErrors)
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

	// Enforce a total timeout for the entire analysis (max 10 hops × ~10s each)
	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	resp, err := service.AnalyzeRedirects(ctx, req)
	if err != nil {
		status := service.ResolveHTTPStatus(err, ctx.Err())
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
