package cache

import (
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
)

// Cache là interface chung cho các bộ nhớ tạm trong hệ thống
type Cache[K comparable, V any] interface {
	Get(key K) (V, bool)
	Set(key K, value V, ttl time.Duration)
	Delete(key K)
}

// memoryCache triển khai Cache interface sử dụng expirable-cache v3
type memoryCache[K comparable, V any] struct {
	base cache.Cache[K, V]
}

// New tạo một bộ nhớ tạm mới với kích thước tối đa và TTL mặc định
func New[K comparable, V any](size int, defaultTTL time.Duration) Cache[K, V] {
	base := cache.NewCache[K, V]().WithMaxKeys(size).WithTTL(defaultTTL).WithLRU()
	return &memoryCache[K, V]{base: base}
}

func (c *memoryCache[K, V]) Get(key K) (V, bool) {
	return c.base.Get(key)
}

func (c *memoryCache[K, V]) Set(key K, value V, ttl time.Duration) {
	c.base.Set(key, value, ttl)
}

func (c *memoryCache[K, V]) Delete(key K) {
	c.base.Invalidate(key)
}

// ============================================
// BACKWARDS COMPATIBILITY CHO CÁC MODULE CŨ
// ============================================

// LegacyCache hỗ trợ interface Get/Set với string key, interface{} value và return (interface{}, time.Time, bool)
type LegacyCache struct {
	base Cache[string, cacheItem]
}

type cacheItem struct {
	data      interface{}
	fetchedAt time.Time
}

func NewMemoryCache(ttl time.Duration) *LegacyCache {
	return &LegacyCache{
		base: New[string, cacheItem](5000, ttl),
	}
}

func (l *LegacyCache) Get(key string) (interface{}, time.Time, bool) {
	if item, found := l.base.Get(key); found {
		return item.data, item.fetchedAt, true
	}
	return nil, time.Time{}, false
}

func (l *LegacyCache) Set(key string, value interface{}) {
	l.base.Set(key, cacheItem{data: value, fetchedAt: time.Now()}, 0) // 0 means default TTL
}

func (l *LegacyCache) Delete(key string) {
	l.base.Delete(key)
}
