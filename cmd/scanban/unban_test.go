package main

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRemoveUnbanned(t *testing.T) {
	var executed bool
	list := UnbanList{mu: new(sync.RWMutex), execute: func(entry UnbanEntry) bool { executed = true; return true }}
	list.Entries = append(list.Entries, UnbanEntry{
		Action: "echo $ip",
		IP:     "1.2.3.4",
		After:  time.Now().Add(-time.Hour),
	}, UnbanEntry{
		Action: "echo $ip",
		IP:     "5.6.7.8",
		After:  time.Now().Add(time.Hour),
	})

	list.Unban()
	assert.True(t, executed)
	assert.Len(t, list.Entries, 1)
	assert.Equal(t, "5.6.7.8", list.Entries[0].IP)
}

func TestFailToRemovedUnbanned(t *testing.T) {
	list := UnbanList{mu: new(sync.RWMutex), execute: func(entry UnbanEntry) bool { return false }}
	list.Entries = append(list.Entries, UnbanEntry{
		Action: "echo $ip",
		IP:     "1.2.3.4",
		After:  time.Now().Add(-time.Hour),
	})

	list.Unban()
	assert.Len(t, list.Entries, 1)
}
