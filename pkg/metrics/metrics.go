package metrics

import (
	"time"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

var (
	Start    time.Time
	Lines    int
	Actioned int
	Errs     int
	Duration float64
)

func Handle(c *scan.Context) {
	Lines++

	if c.OK() {
		Actioned++
	} else {
		Errs++
	}

	if Start.IsZero() {
		Start = time.Now()
	}
}

func Done() {
	Duration = time.Since(Start).Seconds()
}
