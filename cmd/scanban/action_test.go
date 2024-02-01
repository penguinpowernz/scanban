package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	actn := Action{IP: ""}
	assert.ErrorContains(t, actn.Valid(&Config{}), "SKIP empty IP")

	actn = Action{IP: "127.0.0.1"}
	assert.ErrorContains(t, actn.Valid(&Config{Whitelist: []string{"127.0.0.1"}}), "SKIP whitelisted ip: 127.0.0.1")

	actn = Action{IP: "127.0.1ash"}
	assert.ErrorContains(t, actn.Valid(&Config{}), "SKIP invalid IP: 127.0.1ash")

	actn = Action{IP: "101.102.103.104"}
	assert.NoError(t, actn.Valid(&Config{}))
}

func TestCmdString(t *testing.T) {
	actn := Action{Name: "blockit", IP: "101.102.103.104"}
	cmd, ok := actn.CmdString(map[string]string{"blockit": "iptables -I INPUT -s $ip -j DROP"})
	assert.True(t, ok)
	assert.Equal(t, cmd, "iptables -I INPUT -s 101.102.103.104 -j DROP")

	actn = Action{Name: "notify", IP: "101.102.103.104", Desc: "test action"}
	cmd, ok = actn.CmdString(map[string]string{"notify": "notify-send $desc $ip"})
	assert.True(t, ok)
	assert.Equal(t, cmd, "notify-send test action 101.102.103.104")

	actn = Action{Name: "nope", IP: "101.102.103.104"}
	_, ok = actn.CmdString(map[string]string{})
	assert.False(t, ok)
}
