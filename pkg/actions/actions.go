package actions

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

type Action struct {
	name    string
	command string
}

func (a *Action) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	if c.Action == "" {
		c.Err("no action to be done")
		return
	}

	actns := strings.Split(c.Action, ",")
	for _, actn := range actns {
		if actn == a.name {
			a.execute(c)
			c.Actioned = true
		}
	}
}

func (a *Action) execute(c *scan.Context) error {
	if c.DryRun {
		return nil
	}

	cmdstring := strings.ReplaceAll(a.command, "$ip", c.IP)
	cmd := exec.Command("/bin/bash", "-c", cmdstring)
	cmd.Env = append(cmd.Env, "SB_IP="+c.IP)
	// cmd.Env = append(cmd.Env, "SB_DESC="+c.Desc)
	cmd.Env = append(cmd.Env, "SB_BANTIME="+fmt.Sprintf("%d", c.BanTime))
	cmd.Env = append(cmd.Env, "SB_FILENAME="+c.Filename)
	cmd.Env = append(cmd.Env, "SB_LINE="+c.Line)
	// cmd.Env = append(cmd.Env, "SB_NAME="+c.Name)
	cmd.Env = append(cmd.Env, "SB_UNBANACTION="+c.UnbanAction)
	return cmd.Run()
}

type Actions []*Action

func BuildActions(actions map[string]string) Actions {
	aa := new(Actions)
	var x int
	for k, v := range actions {
		*aa = append(*aa, &Action{
			name:    k,
			command: v,
		})
		x++
	}
	return *aa
}

func (a Actions) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	for _, actn := range a {
		actn.Handle(c)
	}
}
