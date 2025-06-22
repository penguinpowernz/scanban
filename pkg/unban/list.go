package unban

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/penguinpowernz/scanban/pkg/scan"
)

func NewList(fn string) (*List, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	list := &List{fn: fn, mu: new(sync.RWMutex)}
	if len(data) > 0 {
		if _, err := toml.Decode(string(data), list); err != nil {
			return nil, err
		}
	}

	list.execute = func(entry UnbanEntry) bool {
		cmd := entry.Cmd()
		if err := cmd.Run(); err != nil {
			log.Printf("failed to unban %s: %s", entry.IP, err)
			return false
		}
		return true
	}

	return list, nil
}

type List struct {
	mu      *sync.RWMutex
	fn      string
	execute func(entry UnbanEntry) bool

	Entries []UnbanEntry `json:"entries"`
}

type UnbanEntry struct {
	Action string    `json:"action"`
	IP     string    `json:"ip"`
	After  time.Time `json:"after"`
}

func (entry *UnbanEntry) Cmd() *exec.Cmd {
	cmdstring := strings.ReplaceAll(entry.Action, "$ip", entry.IP)
	cmd := exec.Command("/bin/bash", "-c", cmdstring)
	cmd.Env = append(cmd.Env, "SB_IP="+entry.IP)
	cmd.Env = append(cmd.Env, "SB_UNBANTIME="+fmt.Sprintf("%d", entry.After.Unix()))
	cmd.Env = append(cmd.Env, "SB_NAME="+entry.Action)
	return cmd
}

func (list *List) unban() {
	list.mu.Lock()
	defer list.mu.Unlock()

	for i := len(list.Entries) - 1; i >= 0; i-- {
		entry := list.Entries[i]
		if time.Now().After(entry.After) {
			log.Printf("Unbanning %s with action %s", entry.IP, entry.Action)
			if list.execute(entry) {
				list.Entries = append(list.Entries[:i], list.Entries[i+1:]...)
			}
		}
	}
}

func (list *List) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	if c.UnbanAction == "" {
		return
	}

	if !c.DryRun {
		list.mu.Lock()
		defer list.mu.Unlock()

		list.Entries = append(list.Entries, UnbanEntry{
			Action: c.UnbanAction,
			IP:     c.IP,
			After:  c.ReleaseTime(),
		})

		if err := list.save(); err != nil {
			log.Printf("failed to save unban list: %s", err)
		}
	}

	c.UnbanScheduled = true
	c.UnbanAt = c.ReleaseTime()
}

func (list *List) save() error {
	list.mu.Lock()
	defer list.mu.Unlock()

	f, err := os.Create(list.fn)
	if err != nil {
		return err
	}
	defer f.Close()

	if err = toml.NewEncoder(f).Encode(list); err != nil {
		return err
	}

	// protect it from external modification
	return f.Chmod(fs.FileMode(0o600))
}
