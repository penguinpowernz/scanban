package logit

import (
	"encoding/json"
	"log"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

func Errors(verb bool) *ELogger {
	return &ELogger{verbose: verb}
}

type ELogger struct{ verbose bool }

func (l *ELogger) Handle(c *scan.Context) {
	if !l.verbose {
		return
	}

	if c.OK() {
		return
	}

	data := struct {
		Err  string `json:"err"`
		Line string `json:"line"`
	}{
		c.Error(),
		c.Line,
	}

	b, err := json.Marshal(data)
	if err != nil {
		log.Println("ELogger: ", err)
		return
	}

	log.Println(string(b))
}
