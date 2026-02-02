package metrics

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/penguinpowernz/scanban/pkg/scan"
	"gopkg.in/yaml.v3"
)

// Global metrics instance
var global = New()

// Metrics holds all runtime statistics
type Metrics struct {
	mu sync.RWMutex

	// Runtime
	StartTime time.Time

	// Totals
	LinesTotal    int
	BansTotal     int
	ErrorsTotal   int
	UniqueIPsSeen map[string]bool
	UniqueIPsBanned map[string]bool

	// Per-file stats
	Files map[string]*FileStats

	// Per-rule stats
	Rules map[string]*RuleStats

	// Per-action stats
	Actions map[string]int

	// Error breakdown
	Errors *ErrorStats

	// Rate limiting
	RateLimiting *RateLimitStats

	// Top banned IPs
	IPBanCounts map[string]int
}

// FileStats tracks metrics for a single log file/container
type FileStats struct {
	Lines   int `yaml:"lines"`
	Matches int `yaml:"matches"`
	Bans    int `yaml:"bans"`
	Errors  int `yaml:"errors"`
}

// RuleStats tracks metrics for a single rule
type RuleStats struct {
	Matches int `yaml:"matches"`
	Bans    int `yaml:"bans"`
}

// ErrorStats tracks different types of errors
type ErrorStats struct {
	Whitelisted         int `yaml:"whitelisted"`
	InvalidIP           int `yaml:"invalid_ip"`
	RateLimitedCooldown int `yaml:"rate_limited_cooldown"`
	RateLimitedGlobal   int `yaml:"rate_limited_global"`
	ThresholdNotMet     int `yaml:"threshold_not_met"`
	ActionFailed        int `yaml:"action_failed"`
	NoMatch             int `yaml:"no_match"`
	Other               int `yaml:"other"`
}

// RateLimitStats tracks rate limiting effectiveness
type RateLimitStats struct {
	CooldownBlocked int `yaml:"cooldown_blocked"`
	GlobalBlocked   int `yaml:"global_blocked"`
}

// StateFile represents the YAML structure written to disk
type StateFile struct {
	UpdatedAt      time.Time              `yaml:"updated_at"`
	UptimeSeconds  float64                `yaml:"uptime_seconds"`
	LinesTotal     int                    `yaml:"lines_total"`
	LinesPerSecond float64                `yaml:"lines_per_second"`
	BansTotal      int                    `yaml:"bans_total"`
	UniqueIPsSeen  int                    `yaml:"unique_ips_seen"`
	UniqueIPsBanned int                   `yaml:"unique_ips_banned"`
	Files          map[string]*FileStats  `yaml:"files"`
	Rules          map[string]*RuleStats  `yaml:"rules"`
	Actions        map[string]int         `yaml:"actions"`
	Errors         *ErrorStats            `yaml:"errors"`
	RateLimiting   *RateLimitStats        `yaml:"rate_limiting"`
	TopBannedIPs   []IPCount              `yaml:"top_banned_ips,omitempty"`
}

// IPCount represents an IP and its ban count
type IPCount struct {
	IP    string `yaml:"ip"`
	Count int    `yaml:"count"`
}

// New creates a new Metrics instance
func New() *Metrics {
	return &Metrics{
		StartTime:       time.Now(),
		UniqueIPsSeen:   make(map[string]bool),
		UniqueIPsBanned: make(map[string]bool),
		Files:           make(map[string]*FileStats),
		Rules:           make(map[string]*RuleStats),
		Actions:         make(map[string]int),
		IPBanCounts:     make(map[string]int),
		Errors: &ErrorStats{},
		RateLimiting: &RateLimitStats{},
	}
}

// Handle processes a scan context and updates metrics
func Handle(c *scan.Context) {
	global.Handle(c)
}

// Handle updates metrics based on the scan context
func (m *Metrics) Handle(c *scan.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Increment line count
	m.LinesTotal++

	// Track unique IPs
	if c.IP != "" {
		m.UniqueIPsSeen[c.IP] = true
	}

	// Per-file stats
	if c.Filename != "" {
		if m.Files[c.Filename] == nil {
			m.Files[c.Filename] = &FileStats{}
		}
		m.Files[c.Filename].Lines++
	}

	// Track matches
	if c.Matched && c.RuleName != "" {
		if m.Rules[c.RuleName] == nil {
			m.Rules[c.RuleName] = &RuleStats{}
		}
		m.Rules[c.RuleName].Matches++

		if c.Filename != "" && m.Files[c.Filename] != nil {
			m.Files[c.Filename].Matches++
		}
	}

	// Track successful bans
	if c.Actioned {
		m.BansTotal++
		if c.IP != "" {
			m.UniqueIPsBanned[c.IP] = true
			m.IPBanCounts[c.IP]++
		}
		if c.RuleName != "" && m.Rules[c.RuleName] != nil {
			m.Rules[c.RuleName].Bans++
		}
		if c.Action != "" {
			m.Actions[c.Action]++
		}
		if c.Filename != "" && m.Files[c.Filename] != nil {
			m.Files[c.Filename].Bans++
		}
	}

	// Track errors
	if !c.OK() {
		m.ErrorsTotal++
		if c.Filename != "" && m.Files[c.Filename] != nil {
			m.Files[c.Filename].Errors++
		}

		// Categorize error types based on error message
		if err := c.GetError(); err != nil {
			errMsg := err.Error()
			switch {
			case contains(errMsg, "whitelisted"):
				m.Errors.Whitelisted++
			case contains(errMsg, "invalid") && contains(errMsg, "IP"):
				m.Errors.InvalidIP++
			case contains(errMsg, "already actioned recently"):
				m.Errors.RateLimitedCooldown++
				m.RateLimiting.CooldownBlocked++
			case contains(errMsg, "global rate limit"):
				m.Errors.RateLimitedGlobal++
				m.RateLimiting.GlobalBlocked++
			case contains(errMsg, "no match"):
				m.Errors.NoMatch++
			case contains(errMsg, "threshold"):
				m.Errors.ThresholdNotMet++
			default:
				m.Errors.Other++
			}
		}
	}
}

// WriteStateFile writes the current metrics to a YAML file
func (m *Metrics) WriteStateFile(path string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uptime := time.Since(m.StartTime).Seconds()
	linesPerSec := 0.0
	if uptime > 0 {
		linesPerSec = float64(m.LinesTotal) / uptime
	}

	state := StateFile{
		UpdatedAt:       time.Now(),
		UptimeSeconds:   uptime,
		LinesTotal:      m.LinesTotal,
		LinesPerSecond:  linesPerSec,
		BansTotal:       m.BansTotal,
		UniqueIPsSeen:   len(m.UniqueIPsSeen),
		UniqueIPsBanned: len(m.UniqueIPsBanned),
		Files:           m.Files,
		Rules:           m.Rules,
		Actions:         m.Actions,
		Errors:          m.Errors,
		RateLimiting:    m.RateLimiting,
		TopBannedIPs:    m.getTopBannedIPs(10),
	}

	data, err := yaml.Marshal(&state)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// getTopBannedIPs returns the top N most banned IPs
func (m *Metrics) getTopBannedIPs(n int) []IPCount {
	// Convert map to slice
	var counts []IPCount
	for ip, count := range m.IPBanCounts {
		counts = append(counts, IPCount{IP: ip, Count: count})
	}

	// Simple bubble sort (good enough for small N)
	for i := 0; i < len(counts); i++ {
		for j := i + 1; j < len(counts); j++ {
			if counts[j].Count > counts[i].Count {
				counts[i], counts[j] = counts[j], counts[i]
			}
		}
	}

	// Return top N
	if len(counts) > n {
		return counts[:n]
	}
	return counts
}

// StartWriter starts a goroutine that writes metrics to file every interval
func StartWriter(ctx context.Context, path string, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Write final state before exiting
			global.WriteStateFile(path)
			return
		case <-ticker.C:
			global.WriteStateFile(path)
		}
	}
}

// contains checks if a string contains a substring (case-insensitive helper)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
		findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Legacy exports for backwards compatibility
var (
	Start    time.Time
	Lines    int
	Actioned int
	Errs     int
	Duration float64
)

func Done() {
	global.mu.RLock()
	defer global.mu.RUnlock()

	Start = global.StartTime
	Lines = global.LinesTotal
	Actioned = global.BansTotal
	Errs = global.ErrorsTotal
	Duration = time.Since(global.StartTime).Seconds()
}
