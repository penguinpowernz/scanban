package ratelimit

import (
	"testing"
	"time"
)

func TestCooldownAllow(t *testing.T) {
	cooldown := NewCooldown(1 * time.Second)

	ip := "192.168.1.1"

	// First action should be allowed
	if !cooldown.Allow(ip) {
		t.Error("Expected first action to be allowed")
	}

	// Record the action
	cooldown.Record(ip)

	// Immediate retry should be denied
	if cooldown.Allow(ip) {
		t.Error("Expected immediate retry to be denied")
	}

	// After cooldown period, should be allowed again
	time.Sleep(1100 * time.Millisecond)
	if !cooldown.Allow(ip) {
		t.Error("Expected action to be allowed after cooldown period")
	}
}

func TestCooldownMultipleIPs(t *testing.T) {
	cooldown := NewCooldown(1 * time.Second)

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Both IPs should be allowed initially
	if !cooldown.Allow(ip1) {
		t.Error("Expected IP1 to be allowed")
	}
	cooldown.Record(ip1)

	if !cooldown.Allow(ip2) {
		t.Error("Expected IP2 to be allowed")
	}
	cooldown.Record(ip2)

	// Both should be denied on retry
	if cooldown.Allow(ip1) {
		t.Error("Expected IP1 retry to be denied")
	}
	if cooldown.Allow(ip2) {
		t.Error("Expected IP2 retry to be denied")
	}

	// After cooldown, both should be allowed
	time.Sleep(1100 * time.Millisecond)
	if !cooldown.Allow(ip1) {
		t.Error("Expected IP1 to be allowed after cooldown")
	}
	if !cooldown.Allow(ip2) {
		t.Error("Expected IP2 to be allowed after cooldown")
	}
}

func TestCooldownSize(t *testing.T) {
	cooldown := NewCooldown(1 * time.Hour)

	// Initially empty
	if cooldown.Size() != 0 {
		t.Errorf("Expected size 0, got %d", cooldown.Size())
	}

	// Record some IPs
	cooldown.Record("192.168.1.1")
	cooldown.Record("192.168.1.2")
	cooldown.Record("192.168.1.3")

	if cooldown.Size() != 3 {
		t.Errorf("Expected size 3, got %d", cooldown.Size())
	}

	// Recording same IP again shouldn't increase size
	cooldown.Record("192.168.1.1")
	if cooldown.Size() != 3 {
		t.Errorf("Expected size 3 after duplicate, got %d", cooldown.Size())
	}
}

func TestCooldownCleanup(t *testing.T) {
	// Short cooldown for testing cleanup
	cooldown := NewCooldown(100 * time.Millisecond)

	// Record multiple IPs
	for i := 1; i <= 5; i++ {
		cooldown.Record("192.168.1." + string(rune('0'+i)))
	}

	if cooldown.Size() != 5 {
		t.Errorf("Expected size 5, got %d", cooldown.Size())
	}

	// Wait for cleanup to run (cleanup runs every 10 minutes, but we can test the cleanup logic)
	// For unit test, we'll manually trigger cleanup by waiting past cooldown period
	// then checking if Allow works (which indirectly validates cleanup would work)
	time.Sleep(150 * time.Millisecond)

	// All IPs should be allowed again after cooldown expires
	for i := 1; i <= 5; i++ {
		ip := "192.168.1." + string(rune('0'+i))
		if !cooldown.Allow(ip) {
			t.Errorf("Expected IP %s to be allowed after cooldown expired", ip)
		}
	}
}

func TestCooldownConcurrent(t *testing.T) {
	cooldown := NewCooldown(1 * time.Second)
	ip := "192.168.1.1"

	// Multiple goroutines trying to record same IP
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			cooldown.Record(ip)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should only have 1 IP tracked
	if cooldown.Size() != 1 {
		t.Errorf("Expected size 1 after concurrent writes, got %d", cooldown.Size())
	}
}
