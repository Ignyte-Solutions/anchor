package v2

import (
	"sync"
	"time"
)

type ReplayCache interface {
	MarkAndCheck(actionID string) (isReplay bool)
}

type WindowedReplayCache interface {
	MarkAndCheckWithinWindow(actionID string, actionTimestamp, referenceTime time.Time, window time.Duration) (isReplay bool)
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

type InMemoryWindowReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func NewInMemoryWindowReplayCache() *InMemoryWindowReplayCache {
	return &InMemoryWindowReplayCache{seen: make(map[string]time.Time)}
}

func (c *InMemoryWindowReplayCache) MarkAndCheck(actionID string) bool {
	return c.MarkAndCheckWithinWindow(actionID, time.Now().UTC(), time.Now().UTC(), 24*time.Hour)
}

func (c *InMemoryWindowReplayCache) MarkAndCheckWithinWindow(actionID string, actionTimestamp, referenceTime time.Time, window time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if window <= 0 {
		window = 5 * time.Minute
	}
	cutoff := referenceTime.UTC().Add(-window)
	for id, ts := range c.seen {
		if ts.Before(cutoff) {
			delete(c.seen, id)
		}
	}
	if _, exists := c.seen[actionID]; exists {
		return true
	}
	c.seen[actionID] = actionTimestamp.UTC()
	return false
}
