package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

// normalizeAndValidate validates + normalizes a ScanRequest. Returns false if it already wrote an error response.
func normalizeAndValidate(c *gin.Context, req *models.ScanRequest) bool {
	// URL Normalization
	req.URL = strings.TrimSpace(req.URL)
	lowerURL := strings.ToLower(req.URL)
	if !strings.HasPrefix(lowerURL, "http://") && !strings.HasPrefix(lowerURL, "https://") {
		req.URL = "https://" + req.URL
	}

	parsedURL, err := url.ParseRequestURI(req.URL)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "URL không hợp lệ")
		return false
	}
	if parsedURL.User != nil {
		response.Error(c, http.StatusBadRequest, "URL không được chứa thông tin đăng nhập (credentials)")
		return false
	}
	if len(req.URL) > 2048 {
		response.Error(c, http.StatusBadRequest, "URL quá dài (vượt quá 2048 ký tự)")
		return false
	}

	// Normalize numeric defaults
	if req.MaxWorkers <= 0 {
		req.MaxWorkers = 10
	}
	if req.MaxDepth <= 0 {
		req.MaxDepth = 2
	}
	if req.MaxPages <= 0 {
		req.MaxPages = 50
	}
	if req.MaxLinks <= 0 {
		req.MaxLinks = 1000
	}
	return true
}

// buildCacheKey returns a deterministic cache key for the given request.
func buildCacheKey(req *models.ScanRequest) string {
	effectiveUA := req.UserAgent
	if effectiveUA == "" {
		effectiveUA = "BCTechVibeBot"
	}
	rawKey := fmt.Sprintf("bls:%s:%s:tls=%v:depth=%d:pages=%d:links=%d:robots=%v:delay=%d:ua=%s",
		strings.ToLower(req.URL), req.Scope, req.IgnoreTlsErrors, req.MaxDepth, req.MaxPages, req.MaxLinks, req.IsRespectRobots(), req.CrawlDelay, effectiveUA)
	return fmt.Sprintf("%x", sha256.Sum256([]byte(rawKey)))
}

func sanitizeLogURL(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, raw)
	runes := []rune(cleaned)
	if len(runes) > 256 {
		return string(runes[:253]) + "..."
	}
	return cleaned
}

// ───────────────────────────────────────────────
// SYNC handler (backward compat)
// ───────────────────────────────────────────────

// HandleScan is the legacy synchronous POST handler.
func HandleScan(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu nhập vào chưa đúng định dạng. Vui lòng kiểm tra lại URL hoặc cấu hình.")
		return
	}
	if !normalizeAndValidate(c, &req) {
		return
	}

	cacheKey := buildCacheKey(&req)
	if !req.BypassCache {
		if data, fetchedAt, found := blsCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
	defer cancel()

	logURL := sanitizeLogURL(req.URL)
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

	// Double-select: prioritize result over context (GEMINI Rule #B-08)
	select {
	case err := <-errChan:
		handleScanError(c, err, logURL)
		return
	case scanData := <-dataChan:
		blsCache.Set(cacheKey, scanData)
		response.Success(c, scanData, false, time.Now())
		return
	default:
	}

	select {
	case err := <-errChan:
		handleScanError(c, err, logURL)
	case scanData := <-dataChan:
		blsCache.Set(cacheKey, scanData)
		response.Success(c, scanData, false, time.Now())
	case <-ctx.Done():
		response.Error(c, http.StatusGatewayTimeout, "Pha thực thi vượt quá giới hạn 60 giây do quá nhiều Links hoặc Server tải quá chậm.")
	}
}

func handleScanError(c *gin.Context, err error, logURL string) {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		response.Error(c, http.StatusGatewayTimeout, "Pha thực thi vượt quá giới hạn 60 giây do quá nhiều Links hoặc Server tải quá chậm.")
		return
	}
	log.Error().Err(err).Str("url", logURL).Msg("broken-link scan error")
	response.Error(c, http.StatusInternalServerError, errutil.TranslateError(err))
}

// ───────────────────────────────────────────────
// ASYNC handlers
// ───────────────────────────────────────────────

// HandleSubmit validates the request and queues an async scan job.
// Returns immediately with a job_id.
// POST /broken-link-scanner/scan/submit
func HandleSubmit(c *gin.Context) {
	var req models.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu nhập vào chưa đúng định dạng. Vui lòng kiểm tra lại URL hoặc cấu hình.")
		return
	}
	if !normalizeAndValidate(c, &req) {
		return
	}

	// Check report cache first — if hit, no need to spawn a job at all
	cacheKey := buildCacheKey(&req)
	if !req.BypassCache {
		if data, fetchedAt, found := blsCache.Get(cacheKey); found {
			c.JSON(http.StatusOK, gin.H{
				"success":    true,
				"job_id":     "",
				"cached":     true,
				"fetched_at": fetchedAt,
				"data":       data,
			})
			return
		}
	}

	job := service.CreateJob(req)
	
	// Hook up caching logic so the service layer caches on success regardless of SSE state
	job.CacheFn = func(finalData models.ScanData) {
		blsCache.Set(cacheKey, finalData)
	}

	c.JSON(http.StatusAccepted, gin.H{
		"success": true,
		"job_id":  job.ID,
	})
}

// HandleStatus streams live progress + final result for an async job using SSE.
// GET /broken-link-scanner/scan/status?job_id=xxx
func HandleStatus(c *gin.Context) {
	jobID := strings.TrimSpace(c.Query("job_id"))
	if jobID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Thiếu job_id"})
		return
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "message": "Không tìm thấy job. Có thể đã hết hạn hoặc ID không đúng."})
		return
	}

	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // disable Nginx buffering
	c.Status(http.StatusOK)

	flusher, canFlush := c.Writer.(http.Flusher)
	writeSSE := func(eventType string, payload any) {
		data, _ := json.Marshal(payload)
		fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", eventType, data)
		if canFlush {
			flusher.Flush()
		}
	}

	clientGone := c.Request.Context().Done()

	// Explicitly start the job if it's currently queued
	service.StartJob(jobID)

	for {
		select {
		case <-clientGone:
			// Just return. We don't cancel automatically anymore, the job might complete
			// and cache itself, or get cleaned up if it was orphaned.
			return

		case ev, open := <-job.ProgressCh:
			if !open {
				// Channel closed → job finished; send final event
				status, data, jobErr := job.GetResult()

				if status == models.JobStatusDone && data != nil {
					writeSSE("done", gin.H{
						"success": true,
						"data":    data,
						"cached":  false,
					})
				} else {
					msg := "Quét thất bại. Vui lòng thử lại."
					if jobErr != nil {
						msg = errutil.TranslateError(jobErr)
						if errors.Is(jobErr, context.DeadlineExceeded) || errors.Is(jobErr, context.Canceled) {
							msg = "Quét vượt quá giới hạn thời gian. Hãy giảm số trang / số link và thử lại."
						}
					}
					writeSSE("scan_error", gin.H{"success": false, "message": msg})
				}
				return
			}
			writeSSE("progress", ev)
		}
	}
}

// HandleCancel allows clients to explicitly cancel a running job
// POST /broken-link-scanner/scan/cancel
func HandleCancel(c *gin.Context) {
	var req struct {
		JobID string `json:"job_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Thiếu job_id")
		return
	}

	job, ok := service.GetJob(req.JobID)
	if ok {
		job.Cancel()
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Đã hủy tác vụ"})
}
