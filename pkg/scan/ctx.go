package scan

import (
	"errors"
	"time"
)

type Context struct {
	Filename       string    `json:"filename"`
	IP             string    `json:"ip"`
	Action         string    `json:"action"`
	Actioned       bool      `json:"actioned"`
	BanTime        int       `json:"bantime"`
	Threshold      int       `json:"threshold"`
	UnbanAction    string    `json:"unban_action"`
	UnbanScheduled bool      `json:"unban_scheduled"`
	UnbanAt        time.Time `json:"unban_at,omitempty"`
	Matched        bool      `json:"matched"`
	Match          string    `json:"match"`
	Line           string    `json:"line"`
	Started        time.Time `json:"started"`
	DryRun         bool
	err            error
}

func (c *Context) Error() string {
	return c.err.Error()
}

func (c *Context) Err(s string) {
	c.err = errors.New(s)
}

// OK returns true if the context has an action, i.e. a rule matched or threshold hit
func (c *Context) OK() bool {
	return c.err == nil
}

// ReleaseTime returns the release time of the ban
func (c *Context) ReleaseTime() time.Time {
	return time.Now().Add(time.Duration(c.BanTime) * time.Hour)
}
