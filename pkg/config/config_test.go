package config

import (
	"regexp"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
)

func TestDropIn(t *testing.T) {
	cfg := &Config{}
	_, err := toml.Decode(cfgData, cfg)
	assert.Nil(t, err)

	assert.Len(t, cfg.Files, 3)

	cfg2 := &Config{}
	_, err = toml.Decode(cfgData2, &cfg2)
	assert.Nil(t, err)

	cfg.Merge(cfg2)
	assert.Len(t, cfg.Files, 4)
}

func TestFullConfigV2(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	assert.Len(t, cfg.Files, 3)
	assert.Contains(t, cfg.Files, "/var/log/auth.log")
	assert.Contains(t, cfg.Files, "/var/log/syslog")
	assert.Contains(t, cfg.Files, "/var/log/ufw.log")

	assert.Len(t, cfg.Actions, 5)
	assert.Contains(t, cfg.Actions, "ipsetunblock")
	assert.Contains(t, cfg.Actions, "ipsetblock")

	assert.Len(t, cfg.Whitelist, 2)
	assert.Contains(t, cfg.Whitelist, "127.0.0.1")
	assert.Contains(t, cfg.Whitelist, "192.168.1.0/24")

	assert.Equal(t, cfg.Bantime, 24)
	assert.Equal(t, cfg.IpRegex, "(\\d+.\\d+.\\d+.\\d+)")
	assert.Equal(t, cfg.Action, "ipsetblock")
	assert.Equal(t, cfg.UnbanAction, "ipsetunblock")
}

func TestRuleCompile(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	assert.Equal(t, cfg.Bantime, 24)
	assert.Equal(t, cfg.IpRegex, "(\\d+.\\d+.\\d+.\\d+)")
	assert.Equal(t, cfg.Action, "ipsetblock")
	assert.Equal(t, cfg.UnbanAction, "ipsetunblock")

	rules := cfg.Rules
	assert.Len(t, rules, 2)
	assert.Len(t, rules[0].Patterns, 1)
	assert.Contains(t, rules[0].Patterns, `IN=\w+ .*DPT=143`)
	assert.Equal(t, rules[0].IpRegex, ` SRC=(\d+\.\d+\.\d+\.\d+) `)
	assert.Equal(t, rules[0].Threshold, 3)
	assert.Equal(t, rules[0].Bantime, 24)
	assert.Equal(t, rules[0].Action, "ipsetblock")
	assert.Equal(t, rules[0].UnbanAction, "ipsetunblock")

	assert.Len(t, rules[1].Patterns, 2)
	assert.Contains(t, rules[1].Patterns, "wp-admin")
	assert.Contains(t, rules[1].Patterns, "phpMyAdmin")
	assert.Equal(t, rules[1].IpRegex, `(\d+.\d+.\d+.\d+)`)
	assert.Equal(t, rules[1].Threshold, 10)
	assert.Equal(t, rules[1].Bantime, 12)
	assert.Equal(t, rules[1].Action, "blockit")
	assert.Equal(t, rules[1].UnbanAction, "unblockit")
}

func TestRuleIPRegex(t *testing.T) {
	cfg, err := Decode([]byte(cfgData))
	assert.Nil(t, err)

	r := cfg.Rules[0]
	re := regexp.MustCompile(r.IpRegex)

	matches := re.FindAllStringSubmatch(" SRC=89.0.142.86 ", -1)
	assert.Equal(t, re.String(), " SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+) ")
	assert.Equal(t, 1, len(matches))
	assert.Equal(t, matches[0][1], "89.0.142.86")
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

	r := cfg.Rules[0]
	re := regexp.MustCompile(r.Pattern)

	line := "[UFW BLOCK] IN=br0 OUT=tun0 SRC=172.31.1.201 DST=172.31.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=38993 DF PROTO=TCP SPT=59772 DPT=143 WINDOW=64240 RES=0x00 SYN URGP=0"
	matches := re.MatchString(line)
	assert.Equal(t, re.String(), `IN=\w+ .*DPT=143`)
	assert.True(t, matches)
}

var cfgData2 = `
files = ["/var/log/kern.log"]

[[rules]]
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
files = [
  "/var/log/syslog",
  "/var/log/auth.log",
  "/var/log/ufw.log"
]

whitelist = [
	"127.0.0.1",
	"192.168.1.0/24"
]

ip_regex = "(\\d+.\\d+.\\d+.\\d+)"
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

[[rules]]
pattern = "IN=\\w+ .*DPT=143"
ip_regex = " SRC=(\\d+\\.\\d+\\.\\d+\\.\\d+) "

[[rules]]
patterns = [
  "wp-admin",
  "phpMyAdmin"
]
bantime = 12
action = "blockit"
unban_action = "unblockit"
threshold = 10
`
