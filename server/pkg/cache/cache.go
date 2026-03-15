package cache

import (
	"sync"
	"time"
)

type Item struct {
	Data      interface{}
	FetchedAt time.Time
}

type MemoryCache struct {
	items map[string]Item
	mutex sync.RWMutex
	ttl   time.Duration
}

func NewMemoryCache(ttl time.Duration) *MemoryCache {
	return &MemoryCache{
		items: make(map[string]Item),
		ttl:   ttl,
	}
}

func (c *MemoryCache) Set(key string, data interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.items[key] = Item{
		Data:      data,
		FetchedAt: time.Now(),
	}
}

func (c *MemoryCache) Get(key string) (interface{}, time.Time, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	item, found := c.items[key]
	if !found {
		return nil, time.Time{}, false
	}
	if time.Since(item.FetchedAt) > c.ttl {
		return nil, time.Time{}, false // Expired
	}
	return item.Data, item.FetchedAt, true
}

func (c *MemoryCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.items, key)
}
