package main

import (
	"fmt"
	"strings"
)

type Action struct {
	Name     string
	IP       string
	Line     string
	Filename string
	Desc     string
}

func (actn *Action) CmdString(actions map[string]string) (string, bool) {
	tmpl, found := actions[actn.Name]
	if !found {
		return "", false
	}
	cmdstring := strings.ReplaceAll(tmpl, "$ip", actn.IP)
	if actn.Desc == "" {
		actn.Desc = "no description"
	}
	return strings.ReplaceAll(cmdstring, "$desc", actn.Desc), true
}

func (actn *Action) Valid(cfg *Config) error {
	if cfg.IsWhitelisted(actn.IP) {
		return fmt.Errorf("SKIP whitelisted ip: %s", actn.IP)
	}

	if actn.IP == "" {
		return fmt.Errorf("SKIP empty IP")
	}

	if !validIP(actn.IP) {
		return fmt.Errorf("SKIP invalid IP: %s", actn.IP)
	}
	return nil
}
