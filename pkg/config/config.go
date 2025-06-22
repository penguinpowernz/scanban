package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

func LoadFile(fn string) (*Config, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	cfg.Compile()
	return &cfg, nil
}

func Decode(data []byte) (*Config, error) {
	cfg := new(Config)
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	cfg.Compile()
	return cfg, nil
}

type Config struct {
	Whitelist   []string          `toml:"whitelist"`
	Actions     map[string]string `toml:"actions"`
	Files       []string          `toml:"files"`
	Bantime     int               `toml:"bantime"`
	IpRegex     string            `toml:"ip_regex"`
	UnbanAction string            `toml:"unban_action"`
	Action      string            `toml:"action"`
	Threshold   int               `toml:"threshold"`
	Rules       []*RuleConfig     `toml:"rules"`
}

func (c *Config) Validate() error {
	// TODO: check all rule actions are valid and exist

	// TODO: check all IPs in the whitelist are valid

	return nil
}

func (c *Config) Compile() {
	for _, rule := range c.Rules {
		rule.Compile(c)
	}
}

func (c *Config) MergeDropin(dir string) {
	if dir != "" {
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if err := c.MergeFile(path); err != nil {
				log.Println("failed to merge", path, err)
				return nil
			}
			log.Println("merged", path)
			return nil
		})
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

	c2, err := LoadFile(filename)
	if err != nil {
		return err
	}

	c.Merge(c2)
	return nil
}

type RuleConfig struct {
	IpRegex     string `toml:"ip_regex,omitempty"`
	Action      string `toml:"action,omitempty"`
	Pattern     string `toml:"pattern"`
	Desc        string `toml:"desc"`
	Threshold   int    `toml:"threshold,omitempty"`
	Bantime     int    `toml:"bantime"`
	UnbanAction string `toml:"unban_action"`

	Patterns []string `toml:"patterns"`
}

func (r *RuleConfig) Compile(cfg *Config) {
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
	if r.Pattern != "" {
		r.Patterns = append(r.Patterns, r.Pattern)
	}
}
