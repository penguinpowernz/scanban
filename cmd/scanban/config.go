package main

import (
	"os"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

func NewConfig(fn string) (*Config, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

type Config struct {
	Whitelist []string          `toml:"whitelist"`
	Actions   map[string]string `toml:"actions"`
	Files     []*FileConfig     `toml:"files"`
	Bantime   int               `toml:"bantime"`
}

func (c *Config) Compile(cfg *Config) {
	for _, file := range c.Files {
		file.Compile(cfg)

		for _, rule := range file.Rules {
			rule.Compile(file)
		}
	}
}

func (c *Config) Merge(cfg *Config) {
	if cfg == nil {
		return
	}
	c.Whitelist = append(c.Whitelist, cfg.Whitelist...)
	for k, v := range cfg.Actions {
		c.Actions[k] = v
	}
	c.Files = append(c.Files, cfg.Files...)
}

func (c *Config) MergeFile(filename string) error {
	if !strings.HasSuffix(filename, ".toml") {
		return nil
	}

	c2, err := NewConfig(filename)
	if err != nil {
		return err
	}

	c.Merge(c2)
	return nil
}

func (c *Config) IsWhitelisted(ip string) bool {
	for _, wip := range c.Whitelist {
		if wip == ip {
			return true
		}
		if strings.Contains(wip, "/") && ipInCIDR(wip, ip) {
			return true
		}
	}
	return false
}

type FileConfig struct {
	Path        string        `toml:"path"`
	IpRegex     string        `toml:"ip_regex"`
	Action      string        `toml:"action"`
	UnbanAction string        `toml:"unban_action"`
	Rules       []*RuleConfig `toml:"rules"`
	Bantime     int           `toml:"bantime"`
	Threshold   int           `toml:"threshold,omitempty"`
}

func (f *FileConfig) Compile(cfg *Config) {
	if f.Bantime == 0 {
		f.Bantime = cfg.Bantime
	}
}

type RuleConfig struct {
	IpRegex     string `toml:"ip_regex,omitempty"`
	Action      string `toml:"action,omitempty"`
	Pattern     string `toml:"pattern"`
	Desc        string `toml:"desc"`
	Threshold   int    `toml:"threshold,omitempty"`
	Bantime     int    `toml:"bantime"`
	UnbanAction string `toml:"unban_action"`

	ipre  *regexp.Regexp
	ptnre *regexp.Regexp

	hits map[string]int
}

func (r *RuleConfig) Compile(cfg *FileConfig) {
	if r.IpRegex == "" {
		r.IpRegex = cfg.IpRegex
	}
	if r.Action == "" {
		r.Action = cfg.Action
	}
	if r.Bantime == 0 {
		r.Bantime = cfg.Bantime
	}
	if r.UnbanAction == "" {
		r.UnbanAction = cfg.UnbanAction
	}
	if r.Threshold == 0 {
		r.Threshold = cfg.Threshold
	}

	r.ipre = regexp.MustCompile(r.IpRegex)
	r.ptnre = regexp.MustCompile(r.Pattern)

	r.hits = make(map[string]int)
}

func (r *RuleConfig) Match(line string) bool {
	return r.ptnre.MatchString(line)
}

func (r *RuleConfig) FindIP(line string) string {
	matches := r.ipre.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// IPHit will register an IP hit with the rule. The returned boolean is false if action should be taken
// or true if it should be ignored.
// If the rule threshold is not set, it is zero meaning action should always be taken.  If the threshold
// is set to 3, then the 4th hit will signal action should be taken.
func (r *RuleConfig) IPHit(ip string) (ignore bool) {
	if r.Threshold == 0 {
		return false
	}
	r.hits[ip]++
	return r.hits[ip] <= r.Threshold
}
