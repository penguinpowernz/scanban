package main

import (
	"io/fs"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

func NewUnbanList(fn string) (*UnbanList, error) {
	data, err := os.ReadFile(fn)
	if err != nil {
		return nil, err
	}

	list := &UnbanList{fn: fn, mu: sync.RWMutex{}}
	if len(data) > 0 {
		if _, err := toml.Decode(string(data), list); err != nil {
			return nil, err
		}
	}

	return list, nil
}

type UnbanList struct {
	mu      sync.RWMutex
	fn      string
	Entries []UnbanEntry `json:"entries"`
}

type UnbanEntry struct {
	Action string    `json:"action"`
	IP     string    `json:"ip"`
	After  time.Time `json:"after"`
}

func (entry *UnbanEntry) Cmd() *exec.Cmd {
	cmdstring := strings.ReplaceAll(entry.Action, "$ip", entry.IP)
	return exec.Command("/bin/bash", "-c", cmdstring)
}

func (list *UnbanList) Unban() {
	list.mu.Lock()
	defer list.mu.Unlock()

	for i := len(list.Entries) - 1; i >= 0; i-- {
		entry := list.Entries[i]
		if time.Now().After(entry.After) {
			log.Printf("Unbanning %s", entry.IP)
			cmd := entry.Cmd()
			if err := cmd.Run(); err != nil {
				log.Printf("failed to unban %s: %s", entry.IP, err)
				continue
			}

			list.Entries = append(list.Entries[:i], list.Entries[i+1:]...)
		}
	}
}

func (list *UnbanList) AddEntry(actn Action) {
	list.mu.Lock()
	defer list.mu.Unlock()

	list.Entries = append(list.Entries, UnbanEntry{
		Action: actn.UnbanAction,
		IP:     actn.IP,
		After:  actn.ReleaseTime(),
	})
}

func (list *UnbanList) Save() error {
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

func unbanLoop(list *UnbanList) {
	for {
		list.Unban()
		list.Save()
		time.Sleep(time.Hour)
	}
}
