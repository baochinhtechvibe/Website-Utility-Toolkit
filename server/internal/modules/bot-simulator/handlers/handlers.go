package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/bot-simulator/models"
	"tools.bctechvibe.com/server/internal/modules/bot-simulator/service"
	"tools.bctechvibe.com/server/internal/response"
)

// HandleAnalyze xử lý request phân tích bot access.
func HandleAnalyze(c *gin.Context) {
	var req models.AnalyzeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Dữ liệu đầu vào không hợp lệ")
		return
	}

	// Validate và chuẩn hóa URL
	normalizedURL, err := service.NormalizeURL(req.URL)
	if err != nil {
		response.Error(c, http.StatusBadRequest, "URL không hợp lệ")
		return
	}

	// Validate bot key
	profile, ok := service.GetProfile(req.Bot)
	if !ok {
		response.Error(c, http.StatusBadRequest, fmt.Sprintf("Bot '%s' không được hỗ trợ", req.Bot))
		return
	}

	// Build cache key
	cacheKey := service.BuildCacheKey(normalizedURL, req.Bot, req.CheckSitemap, req.CompareMode, req.CompareBots)

	// Kiểm tra cache (trừ khi bypassCache=true)
	if !req.BypassCache {
		if cached, fetchedAt, ok := service.CacheGet(cacheKey); ok {
			if data, ok := cached.(*models.AnalyzeData); ok {
				response.Success(c, data, true, fetchedAt)
				return
			}
		}
	} else {
		service.CacheInvalidate(cacheKey)
	}

	// Tạo context với timeout tổng cho toàn bộ request
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	// Thực hiện phân tích
	data, analyzeErr := runAnalysis(ctx, req, normalizedURL, profile)
	if analyzeErr != nil {
		log.Error().Err(analyzeErr).Str("url", normalizedURL).Str("bot", req.Bot).Msg("analyze failed")
		response.Error(c, http.StatusInternalServerError, "Không thể phân tích. Vui lòng thử lại sau.")
		return
	}

	// Lưu cache
	fetchedAt := time.Now()
	service.CacheSet(cacheKey, data)

	response.Success(c, data, false, fetchedAt)
}

// runAnalysis điều phối toàn bộ luồng phân tích.
// TODO: FetchAndParseRobots, FetchPage, CheckSitemap chưa nhận ctx.
// Timeout hiện tại dựa vào http.Client.Timeout nội bộ của từng hàm.
func runAnalysis(ctx context.Context, req models.AnalyzeRequest, targetURL string, profile service.BotProfile) (*models.AnalyzeData, error) {
	data := &models.AnalyzeData{
		Target:      targetURL,
		BotProfile:  profile.ToModelInfo(),
		Limitations: service.DefaultLimitations(),
	}

	fetchOpts := service.FetchOptions{
		UserAgent:       profile.UserAgent,
		ExtraHeaders:    profile.DefaultHeaders,
		IgnoreTLSErrors: req.IgnoreTLSErrors,
		FollowRedirects: true,
	}

	// ─── Bước 1: Fetch robots.txt ─────────────────────────────────────
	robotsResult, _ := service.FetchAndParseRobots(targetURL, profile.UserAgent, req.IgnoreTLSErrors)
	decision := service.CheckRobotsAccess(robotsResult, profile.RobotsToken, targetURL)

	// ─── Bước 2: Fetch trang chính ────────────────────────────────────
	httpResult, fetchErr := service.FetchPage(targetURL, fetchOpts)
	if fetchErr != nil && httpResult == nil {
		// Wrap lỗi network vào serving
		httpResult = &service.HTTPResult{
			FinalURL: targetURL,
			Error:    fetchErr.Error(),
		}
	}

	// ─── Bước 3: Parse meta từ HTML ───────────────────────────────────
	xRobotsTag := ""
	if httpResult.Headers != nil {
		xRobotsTag = service.ParseXRobotsTag(httpResult.Headers)
	}
	meta := service.ParseMeta(httpResult.Body, xRobotsTag, targetURL)

	// ─── Bước 4: Chuẩn bị Serving data ───────────────────────────────
	redirectChain := []models.RedirectHopSummary{}
	for _, hop := range httpResult.RedirectChain {
		redirectChain = append(redirectChain, models.RedirectHopSummary{
			Step:       hop.Step,
			URL:        hop.URL,
			StatusCode: hop.StatusCode,
			StatusText: hop.StatusText,
		})
	}

	serving := models.Serving{
		FinalURL:             httpResult.FinalURL,
		InitialStatusCode:    httpResult.StatusCode,
		InitialStatusText:    httpResult.StatusText,
		ContentType:          httpResult.ContentType,
		PayloadBytes:         httpResult.PayloadBytes,
		RedirectCount:        len(redirectChain) - 1,
		RedirectChainSummary: redirectChain,
		ResponseHeaders:      httpResult.Headers,
		BodySnippet:          httpResult.BodySnippet,
		Title:                meta.Title,
	}
	if serving.RedirectCount < 0 {
		serving.RedirectCount = 0
	}

	// ─── Bước 5: Đánh giá verdict ────────────────────────────────────
	crawlAccess, indexability, verdict := service.EvaluateAccess(decision, robotsResult, &meta, &serving, profile.Family)
	data.CrawlAccess = crawlAccess
	data.Indexability = indexability
	data.Serving = serving
	data.Verdict = verdict

	// ─── Bước 6: Kiểm tra sitemap (nếu được yêu cầu) ─────────────────
	if req.CheckSitemap {
		sitemapResult := service.CheckSitemap(targetURL, robotsResult, profile.UserAgent, req.IgnoreTLSErrors)
		if sitemapResult != nil {
			data.Sitemap = &models.SitemapResult{
				Checked:       true,
				DiscoveryPath: sitemapResult.DiscoveryPath,
				Found:         sitemapResult.Found,
				SitemapURL:    sitemapResult.SitemapURL,
				URLInSitemap:  sitemapResult.URLInSitemap,
				FilesScanned:  sitemapResult.FilesScanned,
				URLsChecked:   sitemapResult.URLsChecked,
				ParseErrors:   sitemapResult.ParseErrors,
			}
		}
	}

	// ─── Bước 7: Compare mode ────────────────────────────────────────
	if req.CompareMode {
		compareBots := req.CompareBots
		if len(compareBots) == 0 {
			compareBots = service.DefaultCompareMatrix
		}

		// Thêm bot hiện tại vào đầu danh sách nếu chưa có
		if !containsString(compareBots, req.Bot) {
			compareBots = append([]string{req.Bot}, compareBots...)
		}

		compareResults := service.RunCompare(ctx, service.CompareOptions{
			BotKeys:         compareBots,
			TargetURL:       targetURL,
			CheckSitemap:    req.CheckSitemap,
			IgnoreTLSErrors: req.IgnoreTLSErrors,
		})
		data.Compare = compareResults
	}

	return data, nil
}

// containsString kiểm tra slice có chứa phần tử không.
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}
