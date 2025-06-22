package rules

import (
	"regexp"

	"github.com/penguinpowernz/scanban/pkg/config"
	"github.com/penguinpowernz/scanban/pkg/scan"
)

type Rule struct {
	Action      string
	UnbanAction string
	BanTime     int
	Threshold   int
	ipre        *regexp.Regexp
	ptns        []*regexp.Regexp
}

func (r *Rule) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	for _, ptn := range r.ptns {
		if ptn.MatchString(c.Line) {
			c.Matched = true
			c.Match = ptn.String()
			break
		}
	}

	if !c.Matched {
		return
	}

	if m := r.ipre.FindStringSubmatch(c.Line); len(m) > 1 && m[1] != "" {
		c.IP = m[1]
	}

	c.Action = r.Action
	c.UnbanAction = r.UnbanAction
	c.BanTime = r.BanTime
	c.Threshold = r.Threshold
}

func newRule(cfg *config.RuleConfig) *Rule {
	return &Rule{
		Action:      cfg.Action,
		UnbanAction: cfg.UnbanAction,
		BanTime:     cfg.Bantime,
		Threshold:   cfg.Threshold,
		ipre:        regexp.MustCompile(cfg.IpRegex),
		ptns: func() []*regexp.Regexp {
			var ptns []*regexp.Regexp
			for _, ptn := range cfg.Patterns {
				ptns = append(ptns, regexp.MustCompile(ptn))
			}
			return ptns
		}(),
	}
}

func BuildRules(cfg []*config.RuleConfig) []*Rule {
	var rules []*Rule
	for _, rule := range cfg {
		rules = append(rules, newRule(rule))
	}
	return rules
}

type Engine struct {
	rules []*Rule
}

func NewEngine(rules []*Rule) *Engine {
	return &Engine{
		rules: rules,
	}
}

func (e *Engine) Handle(c *scan.Context) {
	for _, rule := range e.rules {
		rule.Handle(c)
		if c.Matched {
			break
		}
	}

	if !c.Matched {
		c.Err("no match")
		return
	}

	if c.IP == "" {
		c.Err("no ip found")
		return
	}

	if c.Action == "" {
		c.Err("no action to be done")
		return
	}
}
