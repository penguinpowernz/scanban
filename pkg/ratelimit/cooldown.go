package ratelimit

import (
	"sync"
	"time"
)

// Cooldown tracks recently actioned IPs to prevent re-banning
type Cooldown struct {
	recentBans map[string]time.Time
	period     time.Duration
	mu         sync.RWMutex
}

// NewCooldown creates a new cooldown tracker
// period: minimum time between actions for the same IP
func NewCooldown(period time.Duration) *Cooldown {
	c := &Cooldown{
		recentBans: make(map[string]time.Time),
		period:     period,
	}

	// Start cleanup goroutine
	go c.cleanup()

	return c
}

// Allow checks if an action is allowed for the given IP
// Returns true if the IP hasn't been actioned recently
func (c *Cooldown) Allow(ip string) bool {
	c.mu.RLock()
	lastBan, exists := c.recentBans[ip]
	c.mu.RUnlock()

	if !exists {
		return true
	}

	return time.Since(lastBan) >= c.period
}

// Record marks an IP as recently actioned
func (c *Cooldown) Record(ip string) {
	c.mu.Lock()
	c.recentBans[ip] = time.Now()
	c.mu.Unlock()
}

// cleanup periodically removes old entries from the map
func (c *Cooldown) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for ip, lastBan := range c.recentBans {
			if now.Sub(lastBan) > c.period {
				delete(c.recentBans, ip)
			}
		}
		c.mu.Unlock()
	}
}

// Size returns the number of IPs currently tracked (for testing/debugging)
func (c *Cooldown) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.recentBans)
}
