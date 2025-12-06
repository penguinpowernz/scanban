package logit

import (
	"log"

	"github.com/penguinpowernz/scanban/pkg/scan"
)

func New() *Logger {
	return &Logger{}
}

type Logger struct {
}

func (l *Logger) Handle(c *scan.Context) {
	if !c.OK() {
		return
	}

	// data, err := json.Marshal(c)
	// if err != nil {
	// 	log.Println("Logger: ", err)
	// 	return
	// }

	// log.Println(string(data))
	log.Printf("actioned=%t filename=%-20s ip=%-20s action=%-20s release=%s", c.Actioned, c.Filename, c.IP, c.Action, c.UnbanAt.Format("2006-01-02T15:04"))
}
