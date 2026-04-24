package config

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

func New() *Config {
	cfg := new(Config)
	cfg.DoBans = true
	cfg.DoUnbans = true
	cfg.UnbanList = "/var/lib/unscanban.toml"
	cfg.Include = "/etc/scanban.d"
	cfg.Rules = make(map[string]*RuleConfig)
	cfg.Actions = make(map[string]string)
	return cfg
}

func LoadFile(fn string) (*Config, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}
	var cfg = New()
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	cfg.Compile()
	return cfg, nil
}

func Decode(data []byte) (*Config, error) {
	cfg := New()
	if _, err := toml.Decode(string(data), &cfg); err != nil {
		return nil, err
	}
	cfg.Compile()
	return cfg, nil
}

type Config struct {
	Whitelist   []string          `toml:"whitelist"`
	Actions     map[string]string `toml:"actions"`
	Files       []*FileConfig     `toml:"files"`
	Bantime     int               `toml:"bantime"`
	IpRegex     string            `toml:"ip_regex"`
	UnbanAction string            `toml:"unban_action"`
	Action      string            `toml:"action"`
	Threshold   int               `toml:"threshold"`
	Rules       map[string]*RuleConfig `toml:"rules"`

	DryRun    bool   `toml:"dry_run"`
	Verbose   bool   `toml:"verbose"`
	DoBans    bool   `toml:"do_bans"`
	DoUnbans  bool   `toml:"do_unbans"`
	UnbanList string `toml:"unban_list"`

	Include string `toml:"include"`
}

// FileConfig represents a single log source with its own rules and settings.
// Settings left at zero/empty inherit from the global Config defaults.
type FileConfig struct {
	Path        string   `toml:"path"`
	IpRegex     string   `toml:"ip_regex,omitempty"`
	Action      string   `toml:"action,omitempty"`
	UnbanAction string   `toml:"unban_action,omitempty"`
	Bantime     int      `toml:"bantime,omitempty"`
	Threshold   int      `toml:"threshold,omitempty"`
	Rules       []string `toml:"rules"` // names referencing [rules.name] entries

	// CompiledRules is populated by Compile() — not parsed from TOML.
	CompiledRules []*RuleConfig `toml:"-"`
}

// Compile resolves rule name references and applies three-tier inheritance:
// global defaults → file-level overrides → per-rule overrides.
func (f *FileConfig) Compile(cfg *Config) error {
	// Apply global defaults to file-level fields
	if f.IpRegex == "" {
		f.IpRegex = cfg.IpRegex
	}
	if f.Action == "" {
		f.Action = cfg.Action
	}
	if f.UnbanAction == "" {
		f.UnbanAction = cfg.UnbanAction
	}
	if f.Bantime == 0 {
		f.Bantime = cfg.Bantime
	}
	if f.Threshold == 0 {
		f.Threshold = cfg.Threshold
	}

	// Resolve named rules
	for _, name := range f.Rules {
		rc, ok := cfg.Rules[name]
		if !ok {
			return fmt.Errorf("file %q references unknown rule %q", f.Path, name)
		}
		// Clone the rule config so per-file inheritance doesn't mutate the global map
		compiled := *rc
		// Apply file-level settings as fallback for unset rule fields
		if compiled.IpRegex == "" {
			compiled.IpRegex = f.IpRegex
		}
		if compiled.Action == "" {
			compiled.Action = f.Action
		}
		if compiled.UnbanAction == "" {
			compiled.UnbanAction = f.UnbanAction
		}
		if compiled.Bantime == 0 {
			compiled.Bantime = f.Bantime
		}
		if compiled.Threshold == 0 {
			compiled.Threshold = f.Threshold
		}
		// Normalise single pattern into patterns slice
		if compiled.Pattern != "" {
			compiled.Patterns = append(compiled.Patterns, compiled.Pattern)
		}
		f.CompiledRules = append(f.CompiledRules, &compiled)
	}

	return nil
}

func (c *Config) Validate() error {
	return nil
}

func (c *Config) Encode(w io.Writer) error {
	return toml.NewEncoder(w).Encode(c)
}

func (c *Config) Compile() {
	// First compile named rules against global defaults so their own
	// unset fields are filled in before FileConfig.Compile clones them.
	for _, rule := range c.Rules {
		rule.compileGlobals(c)
	}
	for _, f := range c.Files {
		if err := f.Compile(c); err != nil {
			log.Println("WARNING:", err)
		}
	}
}

// MergeDropin reads all files in the given directory and merges each of them into the config
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

		// Deduplicate files by path
		seen := make(map[string]bool)
		unique := make([]*FileConfig, 0, len(c.Files))
		for _, f := range c.Files {
			if !seen[f.Path] {
				seen[f.Path] = true
				unique = append(unique, f)
			}
		}
		c.Files = unique
	}
}

// Merge merges the given config into the current one
func (c *Config) Merge(cfg *Config) {
	if cfg == nil {
		return
	}
	c.Whitelist = append(c.Whitelist, cfg.Whitelist...)
	for k, v := range cfg.Actions {
		c.Actions[k] = v
	}
	c.Files = append(c.Files, cfg.Files...)
	for k, v := range cfg.Rules {
		c.Rules[k] = v
	}
}

// MergeFile reads the given file and merges it into the config
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

// RuleConfig is the config for a specific named rule
type RuleConfig struct {
	IpRegex     string `toml:"ip_regex,omitempty"`
	Action      string `toml:"action,omitempty"`
	Pattern     string `toml:"pattern,omitempty"`
	Desc        string `toml:"desc,omitempty"`
	Threshold   int    `toml:"threshold,omitempty"`
	Bantime     int    `toml:"bantime,omitempty"`
	UnbanAction string `toml:"unban_action,omitempty"`

	Patterns []string `toml:"patterns,omitempty"`
}

// compileGlobals fills in unset rule fields from global config defaults.
// Called before FileConfig.Compile so clones already have global defaults.
func (r *RuleConfig) compileGlobals(cfg *Config) {
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
}

// String returns a human-readable label for the rule.
// Priority: desc > pattern > first pattern from patterns > "unnamed_rule"
func (r *RuleConfig) String() string {
	if r.Desc != "" {
		return sanitizeLabel(r.Desc)
	}
	if r.Pattern != "" {
		return sanitizeLabel(truncate(r.Pattern, 50))
	}
	if len(r.Patterns) > 0 {
		return sanitizeLabel(truncate(r.Patterns[0], 50))
	}
	return "unnamed_rule"
}

// sanitizeLabel converts a string into a safe metric label
func sanitizeLabel(s string) string {
	var result strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		} else if r == ' ' || r == '-' {
			result.WriteRune('_')
		}
	}
	label := result.String()
	for strings.Contains(label, "__") {
		label = strings.ReplaceAll(label, "__", "_")
	}
	return strings.Trim(label, "_")
}

// truncate truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
