package main

import (
	"log"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/assert"
)

func TestLoadConfig(t *testing.T) {
	cfg := &Config{}
	_, err := toml.Decode(cfgData, cfg)
	assert.Nil(t, err)
	log.Printf("%+v", cfg)

	assert.Contains(t, cfg.Whitelist, "127.0.0.1")
	assert.Contains(t, cfg.Actions, "ipsetblock")

	assert.Len(t, cfg.Files, 3)
	assert.Len(t, cfg.Files[0].Rules, 2)
	assert.Equal(t, cfg.Files[0].Path, "/var/log/auth.log")
	assert.Equal(t, cfg.Files[0].Rules[0].Pattern, "Authentication failed for games")
}

func TestLineMatch(t *testing.T) {
	cfg := &Config{}
	_, err := toml.Decode(cfgData, cfg)
	assert.Nil(t, err)

	badline := `Oct 3 17:36:35 xena kernel: [17213514.504000]tripwire IN=eth1 OUT= MAC=00:03:6d:00:83:cf:00 SRC=2.3.4.5 DST=192.168.1.10 LEN=60 TOS=0x00PREC=0x00 TTL=128 ID=4628 PROTO=TCP DPT=23 CODE=0 ID=512 SEQ=1280`

	r := cfg.Files[2].Rules[0]
	r.Compile(cfg.Files[2])

	assert.True(t, r.Match(badline))
	assert.Equal(t, r.FindIP(badline), "2.3.4.5")

	goodline := "Feb  1 17:18:19 pop-os kernel: [3950260.538941] usb 1-2.1: Warning! Unlikely big volume range (=7248), cval->res is probably wrong."
	assert.False(t, r.Match(goodline))
}

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

func TestWhitelist(t *testing.T) {
	cfg := &Config{Whitelist: []string{"127.0.0.1", "192.168.1.0/24"}}
	assert.True(t, cfg.IsWhitelisted("127.0.0.1"))
	assert.False(t, cfg.IsWhitelisted("89.207.132.170"))
	assert.True(t, cfg.IsWhitelisted("192.168.1.202"))
}

func TestIPHit(t *testing.T) {
	rule := &RuleConfig{
		Threshold: 3,
		hits:      make(map[string]int),
	}

	ignore := rule.IPHit("127.0.0.1")
	assert.True(t, ignore)
	ignore = rule.IPHit("127.0.0.1")
	assert.True(t, ignore)
	ignore = rule.IPHit("127.0.0.1")
	assert.True(t, ignore)
	ignore = rule.IPHit("127.0.0.1")
	assert.False(t, ignore)

	rule = &RuleConfig{Threshold: 0}
	assert.False(t, rule.IPHit("127.0.0.1"))
}

var cfgData = `
whitelist = [
  "127.0.0.1",
  "192.168.1.0/24"
]

[actions]
ipsetblock = "ipset add blockedhosts $ip"

[[files]]
path = "/var/log/auth.log"
ip_regex = "from (\\d+.\\d+.\\d+.\\d+)"
action = "ipsetblock"
rules = [
  { pattern = "Authentication failed for games" },
  { threshold = 10, pattern = "Authentication failed" }
]

[[files]]
path = "/var/log/nginx/error.log"
action = "ipsetblock"
ip_regex = "^(\\d+.\\d+.\\d+.\\d+)"
rules = [
  { pattern = "phpmyadmin" },
  { threshold = 10, pattern = "HTTP/1.1\" 404 " }
]

[[files]]
path = "/var/log/kern.log"
action = "ipsetblock"
ip_regex = "SRC=(\\d+.\\d+.\\d+.\\d+)"
rules = [
  { pattern = "tripwire .* DPT=23 " },
  { pattern = "tripwire .* DPT=21 " },
  { pattern = "tripwire .* DPT=25 " },
  { pattern = "tripwire .* DPT=3389 " }
]
`

var cfgData2 = `
[actions]
iptablesblock = "iptables -I INPUT -s $ip -j DROP"

[[files]]
path = "/var/log/apache2/access.log"
ip_regex = "from (\\d+.\\d+.\\d+.\\d+)"
action = "ipsetblock"
rules = [
  { threshold = 10, pattern = " 404 " }
]
`
