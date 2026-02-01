package ratelimit

import (
	"math"
	"sync"
	"time"
)

// Limiter implements a token bucket rate limiter
type Limiter struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// New creates a new rate limiter with the given parameters
// rate: maximum sustained actions per minute
// burst: maximum burst capacity (actions allowed immediately)
func New(rate, burst int) *Limiter {
	return &Limiter{
		tokens:     float64(burst),
		maxTokens:  float64(burst),
		refillRate: float64(rate) / 60.0, // convert per-minute to per-second
		lastRefill: time.Now(),
	}
}

// Allow returns true if an action is allowed under the rate limit
// It consumes one token if available
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	l.tokens = math.Min(l.maxTokens, l.tokens+elapsed*l.refillRate)
	l.lastRefill = now

	// Check if we have a token available
	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}

	return false
}

// Tokens returns the current number of available tokens (for testing/debugging)
func (l *Limiter) Tokens() float64 {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(l.lastRefill).Seconds()
	tokens := math.Min(l.maxTokens, l.tokens+elapsed*l.refillRate)

	return tokens
}
