package threshold

import (
	"github.com/penguinpowernz/scanban/pkg/scan"
)

func New() *Threshold {
	return &Threshold{
		hits: make(map[string]int),
	}
}

type Threshold struct {
	hits map[string]int
}

func (t *Threshold) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	t.hits[c.IP]++

	if t.hits[c.IP] < c.Threshold {
		c.Err("threshold not met")
		return
	}

	t.hits[c.IP] = 0
}
