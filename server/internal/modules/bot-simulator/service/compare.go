package service

import (
	"context"
	"sync"

	"tools.bctechvibe.com/server/internal/modules/bot-simulator/models"
)

// CompareOptions cấu hình cho compare mode.
type CompareOptions struct {
	BotKeys         []string
	TargetURL       string
	CheckSitemap    bool
	IgnoreTLSErrors bool
}

// RunCompare chạy phân tích đồng thời cho nhiều bot profile.
// Hard cap MaxCompareProfiles để tránh tool tự spam outbound requests.
// Tất cả goroutine dùng chung context cha — nếu timeout/cancel sẽ hủy đồng loạt.
func RunCompare(ctx context.Context, opts CompareOptions) []models.BotCompareResult {
	// Giới hạn số bot chạy
	keys := opts.BotKeys
	if len(keys) > MaxCompareProfiles {
		keys = keys[:MaxCompareProfiles]
	}
	if len(keys) == 0 {
		keys = DefaultCompareMatrix
		if len(keys) > MaxCompareProfiles {
			keys = keys[:MaxCompareProfiles]
		}
	}

	// Sửa lỗi P1 từ review: Không dùng sharedRobots nữa vì robots.txt có thể vary theo User-Agent.
	// Mỗi bot profile phải tự fetch robots.txt bằng chính User-Agent của nó.

	results := make([]models.BotCompareResult, len(keys))
	sem := make(chan struct{}, MaxCompareProfiles) // semaphore kiểm soát concurrency

	var wg sync.WaitGroup
	for i, key := range keys {
		wg.Add(1)
		go func(idx int, botKey string) {
			defer wg.Done()

			// Check context trước khi lấy slot
			select {
			case <-ctx.Done():
				results[idx] = models.BotCompareResult{
					Bot:   botKey,
					Error: "request bị hủy (context cancelled)",
				}
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}

			profile, ok := GetProfile(botKey)
			if !ok {
				results[idx] = models.BotCompareResult{
					Bot:   botKey,
					Error: "bot profile không tìm thấy",
				}
				return
			}

			result := analyzeSingleBot(ctx, profile, opts.TargetURL, opts.CheckSitemap, opts.IgnoreTLSErrors)

			// Safety: Mỗi goroutine ghi vào một index kết quả (idx) độc lập,
			// đồng bộ hóa sau wg.Wait() nên không cần Mutex.
			results[idx] = result
		}(i, key)
	}

	wg.Wait()

	// Tính diff so với bot đầu tiên trong list
	if len(results) > 1 {
		ref := &results[0]
		for i := 1; i < len(results); i++ {
			results[i].Diff = diffResults(ref, &results[i])
		}
	}

	return results
}

// analyzeSingleBot chạy phân tích đầy đủ cho một bot, dùng trong compare mode.
func analyzeSingleBot(ctx context.Context, profile BotProfile, targetURL string, checkSitemap bool, ignoreTLS bool) models.BotCompareResult {
	result := models.BotCompareResult{
		Bot:      profile.Key,
		BotLabel: profile.Label,
	}

	fetchOpts := FetchOptions{
		UserAgent:       profile.UserAgent,
		ExtraHeaders:    profile.DefaultHeaders,
		IgnoreTLSErrors: ignoreTLS,
		FollowRedirects: true,
	}

	// Fetch trang với context
	httpResult, err := FetchPage(ctx, targetURL, fetchOpts)
	if err != nil {
		result.Error = err.Error()
		result.CrawlStatus = CrawlError
		result.IndexStatus = IndexStatusUnknownDueToCrawlBlock
		return result
	}

	result.FinalURL = httpResult.FinalURL
	result.StatusCode = httpResult.StatusCode

	// Hash body để so sánh nội dung
	result.ContentHash = HashBody(httpResult.Body)

	// Parse meta
	xRobots := ParseXRobotsTag(httpResult.Headers)
	meta := ParseMeta(httpResult.Body, xRobots, targetURL, profile.RobotsToken)
	result.Title = meta.Title
	result.Canonical = meta.Canonical
	result.MetaRobots = meta.MetaRobots

	// Kiểm tra robots.txt - Tự fetch riêng bằng UA của bot này
	robotsResult, _ := FetchAndParseRobots(ctx, targetURL, profile.UserAgent, ignoreTLS)
	decision := CheckRobotsAccess(robotsResult, profile.RobotsToken, targetURL)

	// Đánh giá
	serving := &models.Serving{
		FinalURL:          httpResult.FinalURL,
		InitialStatusCode: httpResult.StatusCode,
	}
	crawlAccess, indexability, _ := EvaluateAccess(decision, robotsResult, &meta, serving, profile.RobotsToken, profile.Family)

	result.CrawlStatus = crawlAccess.Status
	result.IndexStatus = indexability.Status

	return result
}

// diffResults so sánh 2 kết quả bot và trả về danh sách điểm khác biệt.
func diffResults(ref *models.BotCompareResult, curr *models.BotCompareResult) []string {
	diffs := []string{}

	if ref.StatusCode != curr.StatusCode {
		diffs = append(diffs, "status_code")
	}
	if ref.FinalURL != curr.FinalURL {
		diffs = append(diffs, "final_url")
	}
	if ref.ContentHash != curr.ContentHash && ref.ContentHash != "" && curr.ContentHash != "" {
		diffs = append(diffs, "content_hash")
	}
	if ref.Title != curr.Title {
		diffs = append(diffs, "title")
	}
	if ref.Canonical != curr.Canonical {
		diffs = append(diffs, "canonical")
	}
	if ref.MetaRobots != curr.MetaRobots {
		diffs = append(diffs, "meta_robots")
	}
	if ref.CrawlStatus != curr.CrawlStatus {
		diffs = append(diffs, "crawl_status")
	}
	if ref.IndexStatus != curr.IndexStatus {
		diffs = append(diffs, "index_status")
	}

	return diffs
}
