package threshold

import (
	"sync"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

func New() *Threshold {
	return &Threshold{
		hits: make(map[string]int),
	}
}

type Threshold struct {
	mu   sync.Mutex
	hits map[string]int
}

func (t *Threshold) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	t.mu.Lock()
	t.hits[c.IP]++
	count := t.hits[c.IP]
	if count >= c.Threshold {
		t.hits[c.IP] = 0
	}
	t.mu.Unlock()

	if count < c.Threshold {
		c.Err("threshold not met")
	}
}
