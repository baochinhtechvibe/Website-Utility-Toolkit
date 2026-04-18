package cache

import (
	"sync"
	"time"
)

type item struct {
	value     interface{}
	createdAt time.Time
	expiresAt time.Time
}

type MemoryCache struct {
	items map[string]item
	mu    sync.RWMutex
	ttl   time.Duration
}

func NewMemoryCache(ttl time.Duration) *MemoryCache {
	c := &MemoryCache{
		items: make(map[string]item),
		ttl:   ttl,
	}

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.items {
				if now.After(v.expiresAt) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}()

	return c
}

func (c *MemoryCache) Get(key string) (interface{}, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	it, ok := c.items[key]
	if !ok || time.Now().After(it.expiresAt) {
		return nil, time.Time{}, false
	}
	return it.value, it.createdAt, true
}

func (c *MemoryCache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.ttl)
}

func (c *MemoryCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.items[key] = item{
		value:     value,
		createdAt: now,
		expiresAt: now.Add(ttl),
	}
}

func (c *MemoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.items, key)
}
