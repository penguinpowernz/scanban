package main

import (
	"log"
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

func (c *Config) MergeFile(filename string) {
	if !strings.HasSuffix(filename, ".toml") {
		return
	}

	c2, err := NewConfig(filename)
	if err != nil {
		log.Println("failed to load", filename, err)
		return
	}

	c.Merge(c2)
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
	Path    string        `toml:"path"`
	IpRegex string        `toml:"ip_regex"`
	Action  string        `toml:"action"`
	Rules   []*RuleConfig `toml:"rules"`
}

type RuleConfig struct {
	IpRegex   string `toml:"ip_regex,omitempty"`
	Action    string `toml:"action,omitempty"`
	Pattern   string `toml:"pattern"`
	Name      string `toml:"name"`
	Threshold int    `toml:"threshold,omitempty"`

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

	r.ipre = regexp.MustCompile(r.IpRegex)
	r.ptnre = regexp.MustCompile(r.Pattern)

	r.hits = make(map[string]int)
}

func (r *RuleConfig) Match(ip string) bool {
	return r.ipre.MatchString(ip)
}

func (r *RuleConfig) FindIP(line string) string {
	matches := r.ipre.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
