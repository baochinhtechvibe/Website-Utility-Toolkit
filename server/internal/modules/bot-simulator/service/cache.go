package service

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/platform/cache"
)

// botSimulatorCache là instance cache riêng cho module này.
// TTL ngắn, đủ để tránh spam outbound nhưng không giữ dữ liệu cũ quá lâu.
var botSimulatorCache = cache.NewMemoryCache(5 * time.Minute)

// CacheGet lấy kết quả từ shared cache.
// Trả về (value, fetchedAt, ok).
func CacheGet(key string) (interface{}, time.Time, bool) {
	return botSimulatorCache.Get(key)
}

// CacheSet lưu kết quả vào cache.
func CacheSet(key string, value interface{}) {
	botSimulatorCache.Set(key, value)
}

// BuildCacheKey xây dựng cache key từ các tham số request.
func BuildCacheKey(targetURL string, botKey string, checkSitemap bool, compareMode bool, compareBots []string) string {
	// Normalize URL để tránh cache miss do trailing slash hoặc fragment
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
	// V2: Sử dụng normalized URL
	return fmt.Sprintf("bot-sim:v2:%s:%s:sitemap=%s:compareMode=%v:compare=%s", normURL, botKey, sitemapStr, compareMode, compareStr)
}

// CacheInvalidate xóa một key khỏi cache (dùng khi bypassCache=true).
func CacheInvalidate(key string) {
	botSimulatorCache.Delete(key)
}
