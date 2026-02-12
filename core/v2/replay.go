package v2

import "sync"

type ReplayCache interface {
	MarkAndCheck(actionID string) (isReplay bool)
}

type InMemoryReplayCache struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

func NewInMemoryReplayCache() *InMemoryReplayCache {
	return &InMemoryReplayCache{seen: make(map[string]struct{})}
}

func (c *InMemoryReplayCache) MarkAndCheck(actionID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.seen[actionID]; exists {
		return true
	}
	c.seen[actionID] = struct{}{}
	return false
}
