package rules

import (
	"regexp"
	"testing"

	"github.com/penguinpowernz/scanban/pkg/config"
	"github.com/penguinpowernz/scanban/pkg/scan"
	"github.com/stretchr/testify/assert"
)

func TestBuildRules(t *testing.T) {
	ruleConfigs := []*config.RuleConfig{
		{
			Patterns:    []string{"wp-admin", "phpMyAdmin"},
			IpRegex:     "(\\d+.\\d+.\\d+.\\d+)",
			Action:      "blockit",
			UnbanAction: "unblockit",
			Bantime:     12,
		},
		{
			Patterns:    []string{"IN=\\w+ .*DPT=143"},
			IpRegex:     " SRC=(\\d+.\\d+.\\d+.\\d+) ",
			Action:      "ipsetblock",
			UnbanAction: "ipsetunblock",
			Bantime:     24,
		},
	}

	rules := BuildRules(ruleConfigs)
	assert.Len(t, rules, 2)

	// Test first rule
	rule1 := rules[0]
	assert.Equal(t, "blockit", rule1.Action)
	assert.Equal(t, "unblockit", rule1.UnbanAction)
	assert.Equal(t, 12, rule1.BanTime)
	assert.Len(t, rule1.ptns, 2)
	assert.Contains(t, rule1.ptns, regexp.MustCompile("wp-admin"))
	assert.Contains(t, rule1.ptns, regexp.MustCompile("phpMyAdmin"))
	assert.Contains(t, rule1.ipre.String(), "(\\d+.\\d+.\\d+.\\d+)")

	// Test second rule
	rule2 := rules[1]
	assert.Equal(t, "ipsetblock", rule2.Action)
	assert.Equal(t, "ipsetunblock", rule2.UnbanAction)
	assert.Equal(t, 24, rule2.BanTime)
	assert.Len(t, rule2.ptns, 1)
	assert.Contains(t, rule2.ptns[0].String(), "IN=\\w+ .*DPT=143")
	assert.Contains(t, rule2.ipre.String(), " SRC=(\\d+.\\d+.\\d+.\\d+) ")
}

func TestRuleHandle(t *testing.T) {
	// First rule test - wp-admin pattern
	ruleConfig1 := &config.RuleConfig{
		Patterns:    []string{"wp-admin"},
		IpRegex:     "(\\d+.\\d+.\\d+.\\d+)",
		Action:      "blockit",
		UnbanAction: "unblockit",
		Bantime:     12,
	}
	rule1 := newRule(ruleConfig1)

	ctx1 := &scan.Context{
		Line: "GET /wp-admin/some-path HTTP/1.1 from 192.168.1.100",
	}
	rule1.Handle(ctx1)
	assert.Equal(t, "blockit", ctx1.Action)
	assert.Equal(t, "unblockit", ctx1.UnbanAction)
	assert.Equal(t, 12, ctx1.BanTime)
	assert.Equal(t, "192.168.1.100", ctx1.IP)

	// Second rule test - failed match
	ctx2 := &scan.Context{
		Line: "Some unrelated log line",
	}
	rule1.Handle(ctx2)
	assert.Equal(t, "", ctx2.Action)
	assert.Equal(t, "", ctx2.UnbanAction)
	assert.Equal(t, 0, ctx2.BanTime)
	assert.Equal(t, "", ctx2.IP)

	// Third rule test - SSH pattern
	ruleConfig2 := &config.RuleConfig{
		Patterns:    []string{"sshd.*Invalid user \\w+ from"},
		IpRegex:     "from (\\d+.\\d+.\\d+.\\d+)",
		Action:      "ipsetblock",
		UnbanAction: "ipsetunblock",
		Bantime:     24,
	}
	rule2 := newRule(ruleConfig2)

	ctx3 := &scan.Context{
		Line: "Jun 21 12:54:36 tunnel sshd[27262]: Invalid user root from 195.178.110.160",
	}
	rule2.Handle(ctx3)
	assert.Equal(t, "ipsetblock", ctx3.Action)
	assert.Equal(t, "ipsetunblock", ctx3.UnbanAction)
	assert.Equal(t, 24, ctx3.BanTime)
	assert.Equal(t, "195.178.110.160", ctx3.IP)
}

func TestRuleEngine(t *testing.T) {
	ruleConfigs := []*config.RuleConfig{
		{
			Patterns:    []string{"wp-admin"},
			IpRegex:     "(\\d+.\\d+.\\d+.\\d+)",
			Action:      "blockit",
			UnbanAction: "unblockit",
			Bantime:     12,
		},
		{
			Patterns:    []string{"sshd.*Invalid user \\w+ from"},
			IpRegex:     "from (\\d+.\\d+.\\d+.\\d+)",
			Action:      "ipsetblock",
			UnbanAction: "ipsetunblock",
			Bantime:     24,
		},
	}
	rules := BuildRules(ruleConfigs)
	engine := NewEngine(rules)

	// Test engine handles multiple rules
	ctx := &scan.Context{
		Line: "GET /wp-admin/some-path HTTP/1.1 from 192.168.1.100",
	}
	engine.Handle(ctx)
	assert.Equal(t, "blockit", ctx.Action)
	assert.Equal(t, "unblockit", ctx.UnbanAction)
	assert.Equal(t, 12, ctx.BanTime)
	assert.Equal(t, "192.168.1.100", ctx.IP)
}

func TestRuleIPRegex(t *testing.T) {
	rule := &Rule{ptns: []*regexp.Regexp{regexp.MustCompile(`GET`)}}

	rule.ipre = regexp.MustCompile(`(\d+.\d+.\d+.\d+)`)
	c := &scan.Context{Line: "GET /wp-admin/some-path HTTP/1.1 from 38.0.101.76"}
	rule.Handle(c)
	assert.Equal(t, "38.0.101.76", c.IP)

	rule.ipre = regexp.MustCompile(`from (\d+.\d+.\d+.\d+)`)
	c = &scan.Context{Line: "GET /wp-admin/some-path HTTP/1.1 from 38.0.101.76"}
	rule.Handle(c)
	assert.Equal(t, "38.0.101.76", c.IP)

	rule.ipre = regexp.MustCompile(`banana (\d+.\d+.\d+.\d+)`)
	c = &scan.Context{Line: "GET /wp-admin/some-path HTTP/1.1 from 38.0.101.76"}
	rule.Handle(c)
	assert.Equal(t, "", c.IP)
}
