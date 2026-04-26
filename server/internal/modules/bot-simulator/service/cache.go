package service

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/bot-simulator/models"
	"tools.bctechvibe.com/server/internal/platform/cache"
)

// cachedResult bọc dữ liệu phân tích kèm thời điểm fetch (Rule #11 & #33).
type cachedResult struct {
	Data      *models.AnalyzeData
	FetchedAt time.Time
}

// botSimulatorCache sử dụng Generic Cache với size 1000 và TTL 10 phút.
var botSimulatorCache = cache.New[string, cachedResult](1000, 10*time.Minute)

// CacheGet lấy kết quả từ cache.
func CacheGet(key string) (*models.AnalyzeData, time.Time, bool) {
	if val, ok := botSimulatorCache.Get(key); ok {
		return val.Data, val.FetchedAt, true
	}
	return nil, time.Time{}, false
}

// CacheSet lưu kết quả vào cache.
func CacheSet(key string, value *models.AnalyzeData) {
	botSimulatorCache.Set(key, cachedResult{
		Data:      value,
		FetchedAt: time.Now(),
	}, 0) // 0 để dùng default TTL
}

// BuildCacheKey xây dựng cache key an toàn bằng SHA256 (Rule #56 & #304).
func BuildCacheKey(targetURL string, botKey string, checkSitemap bool, compareMode bool, compareBots []string) string {
	normURL, _ := NormalizeURL(targetURL)
	if normURL == "" {
		normURL = targetURL
	}

	sortedBots := make([]string, len(compareBots))
	copy(sortedBots, compareBots)
	sort.Strings(sortedBots)
	compareStr := strings.Join(sortedBots, ",")
	
	sitemapStr := "0"
	if checkSitemap {
		sitemapStr = "1"
	}

	// Tạo chuỗi raw chứa toàn bộ tham số định danh request
	rawKey := fmt.Sprintf("bot-sim:v3:%s:%s:sitemap=%s:compareMode=%v:compare=%s", 
		normURL, botKey, sitemapStr, compareMode, compareStr)

	// Băm SHA256 để có key an toàn và độ dài cố định
	hash := sha256.Sum256([]byte(rawKey))
	return fmt.Sprintf("bsim_%x", hash)
}

// CacheInvalidate xóa một key khỏi cache.
func CacheInvalidate(key string) {
	botSimulatorCache.Delete(key)
}
