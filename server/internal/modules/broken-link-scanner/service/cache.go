package service

import (
	"crypto/sha256"
	"fmt"
	"time"

	"tools.bctechvibe.com/server/internal/platform/cache"
)

// ScannerCache holds cached results for external/internal asset checks.
// Cache items TTL is somewhat long since static assets don't break often within 30 minutes.
var ScannerCache = cache.NewMemoryCache(30 * time.Minute)

// CacheGet reads an item
func CacheGet(key string) (interface{}, time.Time, bool) {
	return ScannerCache.Get(key)
}

// CacheSet sets an item
func CacheSet(key string, value interface{}) {
	ScannerCache.Set(key, value)
}

// BuildCacheKey generates a cache key for an individual URL check.
// We hash the URL to prevent overly long keys or special character problems.
func BuildCacheKey(assetURL string, ignoreTLS bool) string {
	hash := sha256.Sum256([]byte(assetURL))
	return fmt.Sprintf("broken_asset:%x:tls=%v", hash, ignoreTLS)
}

// CacheInvalidate removes an item
func CacheInvalidate(key string) {
	ScannerCache.Delete(key)
}
