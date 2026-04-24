package config

import (
	"regexp"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
)

func TestDropIn(t *testing.T) {
	cfg := &Config{Rules: make(map[string]*RuleConfig), Actions: make(map[string]string)}
	_, err := toml.Decode(cfgData, cfg)
	assert.Nil(t, err)

	assert.Len(t, cfg.Files, 3)

	cfg2 := &Config{Rules: make(map[string]*RuleConfig), Actions: make(map[string]string)}
	_, err = toml.Decode(cfgData2, &cfg2)
	assert.Nil(t, err)

	cfg.Merge(cfg2)
	assert.Len(t, cfg.Files, 4)
}

func TestFullConfigV2(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	assert.Len(t, cfg.Files, 3)
	assert.Equal(t, "/var/log/syslog", cfg.Files[0].Path)
	assert.Equal(t, "/var/log/auth.log", cfg.Files[1].Path)
	assert.Equal(t, "/var/log/ufw.log", cfg.Files[2].Path)

	assert.Len(t, cfg.Actions, 5)
	assert.Contains(t, cfg.Actions, "ipsetunblock")
	assert.Contains(t, cfg.Actions, "ipsetblock")

	assert.Len(t, cfg.Whitelist, 2)
	assert.Contains(t, cfg.Whitelist, "127.0.0.1")
	assert.Contains(t, cfg.Whitelist, "192.168.1.0/24")

	assert.Equal(t, cfg.Bantime, 24)
	assert.Equal(t, cfg.IpRegex, `(\d+\.\d+\.\d+\.\d+)`)
	assert.Equal(t, cfg.Action, "ipsetblock")
	assert.Equal(t, cfg.UnbanAction, "ipsetunblock")
}

func TestRuleCompile(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	assert.Equal(t, cfg.Bantime, 24)
	assert.Equal(t, cfg.IpRegex, `(\d+\.\d+\.\d+\.\d+)`)
	assert.Equal(t, cfg.Action, "ipsetblock")
	assert.Equal(t, cfg.UnbanAction, "ipsetunblock")

	// firewall file: one rule (ufw_block) with custom ip_regex
	fwFile := cfg.Files[2] // /var/log/ufw.log
	assert.Len(t, fwFile.CompiledRules, 1)
	ufw := fwFile.CompiledRules[0]
	assert.Len(t, ufw.Patterns, 1)
	assert.Contains(t, ufw.Patterns, `IN=\w+ .*DPT=143`)
	assert.Equal(t, ` SRC=(\d+\.\d+\.\d+\.\d+) `, ufw.IpRegex)
	assert.Equal(t, 3, ufw.Threshold)
	assert.Equal(t, 24, ufw.Bantime)
	assert.Equal(t, "ipsetblock", ufw.Action)
	assert.Equal(t, "ipsetunblock", ufw.UnbanAction)

	// auth file: one rule (wp_scan) with overridden action and bantime
	authFile := cfg.Files[1] // /var/log/auth.log
	assert.Len(t, authFile.CompiledRules, 1)
	wp := authFile.CompiledRules[0]
	assert.Len(t, wp.Patterns, 2)
	assert.Contains(t, wp.Patterns, "wp-admin")
	assert.Contains(t, wp.Patterns, "phpMyAdmin")
	assert.Equal(t, `(\d+\.\d+\.\d+\.\d+)`, wp.IpRegex)
	assert.Equal(t, 10, wp.Threshold)
	assert.Equal(t, 12, wp.Bantime)
	assert.Equal(t, "blockit", wp.Action)
	assert.Equal(t, "unblockit", wp.UnbanAction)
}

func TestRuleIPRegex(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	// ufw_block rule has the custom SRC= ip_regex
	fwFile := cfg.Files[2]
	r := fwFile.CompiledRules[0]
	re := regexp.MustCompile(r.IpRegex)

	matches := re.FindAllStringSubmatch(" SRC=89.0.142.86 ", -1)
	assert.Equal(t, ` SRC=(\d+\.\d+\.\d+\.\d+) `, re.String())
	assert.Equal(t, 1, len(matches))
	assert.Equal(t, "89.0.142.86", matches[0][1])
}

func TestLoadActions(t *testing.T) {
	cfg, err := Decode([]byte(cfgData2))
	assert.Nil(t, err)
	assert.Len(t, cfg.Actions, 2)
	assert.Contains(t, cfg.Actions, "httpblock")
	assert.Contains(t, cfg.Actions, "httpunblock")
}

func TestRulePtnRegex(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	fwFile := cfg.Files[2]
	r := fwFile.CompiledRules[0]
	re := regexp.MustCompile(r.Patterns[0])

	line := "[UFW BLOCK] IN=br0 OUT=tun0 SRC=172.31.1.201 DST=172.31.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=38993 DF PROTO=TCP SPT=59772 DPT=143 WINDOW=64240 RES=0x00 SYN URGP=0"
	matches := re.MatchString(line)
	assert.Equal(t, `IN=\w+ .*DPT=143`, re.String())
	assert.True(t, matches)
}

func TestRuleConfigString(t *testing.T) {
	tests := []struct {
		name string
		rule *RuleConfig
		want string
	}{
		{
			name: "uses desc if provided",
			rule: &RuleConfig{Desc: "SSH Bruteforce Attack"},
			want: "ssh_bruteforce_attack",
		},
		{
			name: "uses pattern if no desc",
			rule: &RuleConfig{Pattern: "Failed password for"},
			want: "failed_password_for",
		},
		{
			name: "uses first pattern from patterns if no desc or pattern",
			rule: &RuleConfig{Patterns: []string{"wp-admin", "phpMyAdmin"}},
			want: "wp_admin",
		},
		{
			name: "returns unnamed_rule if nothing provided",
			rule: &RuleConfig{},
			want: "unnamed_rule",
		},
		{
			name: "sanitizes special characters",
			rule: &RuleConfig{Desc: "Test-Rule_With/Special\\Chars!"},
			want: "test_rulewithspecialchars",
		},
		{
			name: "handles regex patterns",
			rule: &RuleConfig{Pattern: "sshd.*Invalid user \\w+ from"},
			want: "sshdinvalid_user_w_from",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMergeRules(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)
	assert.Len(t, cfg.Rules, 2)

	cfg2, err := Decode([]byte(cfgData2))
	assert.Nil(t, err)
	assert.Len(t, cfg2.Rules, 1)

	cfg.Merge(cfg2)
	assert.Len(t, cfg.Rules, 3)
	assert.Contains(t, cfg.Rules, "ufw_block")
	assert.Contains(t, cfg.Rules, "wp_scan")
	assert.Contains(t, cfg.Rules, "auth_fail")
}

// cfgData2 is a drop-in style config: adds one file, one rule, some actions.
var cfgData2 = `
[[files]]
path = "/var/log/kern.log"
rules = ["auth_fail"]

[rules.auth_fail]
pattern = "Authentication failed"
bantime = 1

whitelist = [
	"10.0.0.0/24"
]

[actions]
httpblock = "do something"
httpunblock = "do something else"
`

var cfgData = `
whitelist = [
	"127.0.0.1",
	"192.168.1.0/24"
]

ip_regex = '(\d+\.\d+\.\d+\.\d+)'
bantime = 24
threshold = 3
action = "ipsetblock"
unban_action = "ipsetunblock"

[actions]
blockit = "iptables -A INPUT -s $ip -j DROP && iptables -A OUTPUT -d $ip -j DROP"
unblockit = "iptables -D INPUT -s $ip -j DROP && iptables -D OUTPUT -d $ip -j DROP"
notify = "pingslack"
ipsetblock = "ipset add scanban $ip"
ipsetunblock = "ipset del scanban $ip"

[rules.ufw_block]
pattern = 'IN=\w+ .*DPT=143'
ip_regex = ' SRC=(\d+\.\d+\.\d+\.\d+) '

[rules.wp_scan]
patterns = [
  "wp-admin",
  "phpMyAdmin"
]
bantime = 12
action = "blockit"
unban_action = "unblockit"
threshold = 10

[[files]]
path = "/var/log/syslog"

[[files]]
path = "/var/log/auth.log"
rules = ["wp_scan"]

[[files]]
path = "/var/log/ufw.log"
rules = ["ufw_block"]
`
