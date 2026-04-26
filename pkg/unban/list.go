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
	"github.com/penguinpowernz/scanban/pkg/sanitize"
	"github.com/penguinpowernz/scanban/pkg/scan"
)

func NewList(fn string, do bool) (*List, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	list := &List{fn: fn, mu: new(sync.RWMutex), doUnbans: do}
	if len(data) > 0 {
		if _, err := toml.Decode(string(data), list); err != nil {
			return nil, err
		}
	}

	list.execute = func(entry UnbanEntry) bool {
		cmd := entry.Cmd()
		if cmd == nil {
			log.Printf("skipping unban for invalid IP %q", entry.IP)
			return true // remove the entry — it can never be executed safely
		}
		if err := cmd.Run(); err != nil {
			log.Printf("failed to unban %s: %s", entry.IP, err)
			return false
		}
		return true
	}

	return list, nil
}

type List struct {
	mu       *sync.RWMutex
	fn       string
	doUnbans bool
	execute  func(entry UnbanEntry) bool

	Entries []UnbanEntry `json:"entries"`
}

type UnbanEntry struct {
	Action string    `json:"action"`
	IP     string    `json:"ip"`
	After  time.Time `json:"after"`
}

func (entry *UnbanEntry) Cmd() *exec.Cmd {
	safeIP := sanitize.IP(entry.IP)
	if safeIP == "" {
		return nil
	}
	cmdstring := strings.ReplaceAll(entry.Action, "$ip", safeIP)
	cmd := exec.Command("/bin/bash", "-c", cmdstring)
	cmd.Env = append(cmd.Env, "SB_IP="+safeIP)
	cmd.Env = append(cmd.Env, "SB_UNBANTIME="+fmt.Sprintf("%d", entry.After.Unix()))
	cmd.Env = append(cmd.Env, "SB_NAME="+entry.Action)
	return cmd
}

func (list *List) unban() {
	list.mu.Lock()
	now := time.Now()
	for i := len(list.Entries) - 1; i >= 0; i-- {
		entry := list.Entries[i]
		if now.After(entry.After) {
			log.Printf("Unbanning %s with action %s", entry.IP, entry.Action)
			if list.execute(entry) {
				list.Entries = append(list.Entries[:i], list.Entries[i+1:]...)
			}
		}
	}
	list.mu.Unlock()
}

func (list *List) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	if c.UnbanAction == "" {
		return
	}

	if !list.doUnbans {
		return
	}

	if !c.DryRun {
		list.mu.Lock()
		list.Entries = append(list.Entries, UnbanEntry{
			Action: c.UnbanAction,
			IP:     c.IP,
			After:  c.ReleaseTime(),
		})
		err := list.saveUnlocked()
		list.mu.Unlock()
		if err != nil {
			log.Printf("failed to save unban list: %s", err)
		}
	}

	c.UnbanScheduled = true
	c.UnbanAt = c.ReleaseTime()
}

// save acquires the lock and writes the list to disk.
func (list *List) save() error {
	list.mu.Lock()
	defer list.mu.Unlock()
	return list.saveUnlocked()
}

// saveUnlocked writes the list to disk. Caller must hold list.mu.
func (list *List) saveUnlocked() error {
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
