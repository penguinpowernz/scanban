package once

import (
	"crypto/md5"
	"sync"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

const windowSize = 50

var (
	mu     sync.Mutex
	ring   [windowSize]string // circular buffer of hash strings
	head   int                // next slot to write
	count  int                // number of valid entries in ring (0..windowSize)
	seen   = make(map[string]bool)
)

func Handle(c *scan.Context) {
	sum := md5.Sum([]byte(c.Line))
	hash := string(sum[:])

	mu.Lock()
	defer mu.Unlock()

	if seen[hash] {
		c.Err("already seen")
		return
	}

	// Evict the oldest entry when the window is full
	if count == windowSize {
		oldest := ring[head]
		delete(seen, oldest)
	} else {
		count++
	}

	// Write the new hash into the ring at head and advance
	ring[head] = hash
	head = (head + 1) % windowSize
	seen[hash] = true
}
