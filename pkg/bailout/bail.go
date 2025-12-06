package bailout

import (
	"log"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

var count int

func Handle(c *scan.Context) {
	if len(c.Line) == 0 {
		count++
	}

	if count > 5 {
		log.Fatal("5 empty lines, bailing out")
	}
}
