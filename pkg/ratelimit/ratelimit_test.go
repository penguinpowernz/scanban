package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterBurst(t *testing.T) {
	// Create limiter: 60/min, burst 10
	limiter := New(60, 10)

	// Should allow burst of 10 immediately
	for i := 0; i < 10; i++ {
		if !limiter.Allow() {
			t.Errorf("Expected action %d to be allowed in burst", i+1)
		}
	}

	// 11th action should be denied (burst exhausted)
	if limiter.Allow() {
		t.Error("Expected 11th action to be denied after burst")
	}
}

func TestLimiterRefill(t *testing.T) {
	// Create limiter: 60/min = 1/sec, burst 2
	limiter := New(60, 2)

	// Consume burst
	limiter.Allow()
	limiter.Allow()

	// Should be denied immediately
	if limiter.Allow() {
		t.Error("Expected action to be denied before refill")
	}

	// Wait for 1 token to refill (1 second at 60/min rate)
	time.Sleep(1100 * time.Millisecond)

	// Should now allow 1 action
	if !limiter.Allow() {
		t.Error("Expected action to be allowed after refill")
	}

	// Should be denied again
	if limiter.Allow() {
		t.Error("Expected action to be denied after consuming refilled token")
	}
}

func TestLimiterTokens(t *testing.T) {
	limiter := New(60, 10)

	// Initial tokens should be ~10
	tokens := limiter.Tokens()
	if tokens < 9.9 || tokens > 10.0 {
		t.Errorf("Expected ~10 initial tokens, got %f", tokens)
	}

	// Consume some tokens
	limiter.Allow()
	limiter.Allow()
	limiter.Allow()

	tokens = limiter.Tokens()
	if tokens < 6.9 || tokens > 7.1 {
		t.Errorf("Expected ~7 tokens after consuming 3, got %f", tokens)
	}
}

func TestLimiterConcurrent(t *testing.T) {
	limiter := New(60, 10)
	allowed := make(chan bool, 20)

	// Try to consume tokens concurrently
	for i := 0; i < 20; i++ {
		go func() {
			allowed <- limiter.Allow()
		}()
	}

	// Count how many were allowed
	count := 0
	for i := 0; i < 20; i++ {
		if <-allowed {
			count++
		}
	}

	// Should allow exactly 10 (burst capacity)
	if count != 10 {
		t.Errorf("Expected exactly 10 concurrent actions allowed, got %d", count)
	}
}

func TestLimiterSustainedRate(t *testing.T) {
	// Create limiter: 120/min = 2/sec, burst 5
	limiter := New(120, 5)

	// Consume burst
	for i := 0; i < 5; i++ {
		limiter.Allow()
	}

	// Over 2 seconds, should allow ~4 more actions (2/sec)
	time.Sleep(2100 * time.Millisecond)

	allowed := 0
	for i := 0; i < 10; i++ {
		if limiter.Allow() {
			allowed++
		}
	}

	// Should allow 4-5 actions (2/sec * 2 sec, with some tolerance)
	if allowed < 3 || allowed > 5 {
		t.Errorf("Expected ~4 actions over 2 seconds, got %d", allowed)
	}
}
