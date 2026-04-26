package actions

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/penguinpowernz/scanban/pkg/ratelimit"
	"github.com/penguinpowernz/scanban/pkg/sanitize"
	"github.com/penguinpowernz/scanban/pkg/scan"
)

var (
	// Global rate limiter: 60 actions/minute sustained, burst of 10
	globalLimiter = ratelimit.New(60, 10)

	// Per-IP cooldown: prevent re-banning same IP within 1 hour
	ipCooldown = ratelimit.NewCooldown(1 * time.Hour)
)

// Action represents a single action that may
// be taken by the rules.  It has a name and
// the actual command to be executed
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
			if err := a.execute(c); err != nil {
				c.Err(err.Error())
				return
			}
			c.Actioned = true
		}
	}
}

func (a *Action) execute(c *scan.Context) error {
	// Sanitize IP to prevent command injection (always validate, even in dry run)
	safeIP := sanitize.IP(c.IP)
	if safeIP == "" {
		return fmt.Errorf("invalid or dangerous IP address: %s", c.IP)
	}

	// In dry run mode, skip rate limiting and actual execution
	if c.DryRun {
		return nil
	}

	// Check per-IP cooldown first (doesn't consume tokens)
	if !ipCooldown.Allow(safeIP) {
		return fmt.Errorf("IP %s already actioned recently, skipping", safeIP)
	}

	// Check global rate limit (consumes token)
	if !globalLimiter.Allow() {
		return fmt.Errorf("global rate limit exceeded, action dropped for IP %s", safeIP)
	}

	cmdstring := strings.ReplaceAll(a.command, "$ip", safeIP)
	cmd := exec.Command("/bin/bash", "-c", cmdstring)
	cmd.Env = append(cmd.Env, "SB_IP="+safeIP)
	cmd.Env = append(cmd.Env, "SB_BANTIME="+fmt.Sprintf("%d", c.BanTime))
	cmd.Env = append(cmd.Env, "SB_FILENAME="+sanitize.EnvVar(c.Filename))
	cmd.Env = append(cmd.Env, "SB_LINE="+sanitize.EnvVar(c.Line))
	cmd.Env = append(cmd.Env, "SB_UNBANACTION="+sanitize.EnvVar(c.UnbanAction))

	err := cmd.Run()

	// Record the IP in cooldown tracker only if action succeeded
	if err == nil {
		ipCooldown.Record(safeIP)
	}

	return err
}

type Actions struct {
	actions []*Action
	doBans  bool
}

func BuildActions(actions map[string]string, do bool) *Actions {
	aa := &Actions{doBans: do}
	for k, v := range actions {
		aa.actions = append(aa.actions, &Action{
			name:    k,
			command: v,
		})
	}
	return aa
}

func (a *Actions) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	if !a.doBans {
		return
	}

	for _, actn := range a.actions {
		actn.Handle(c)
		if !c.OK() {
			return
		}
	}
}
