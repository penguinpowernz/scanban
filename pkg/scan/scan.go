package scan

import (
	"context"
	"sync"
	"time"

	"github.com/penguinpowernz/scanban/pkg/config"
)

func BuildScanners(files []*config.FileConfig, dryRun bool, engineFor func(*config.FileConfig) Handler) Scanners {
	s := &Scanners{}
	for _, fc := range files {
		t, err := NewTailerFromFileConfig(fc.Path)
		if err != nil {
			continue
		}
		*s = append(*s, &Scanner{
			Filename: fc.Path,
			engine:   engineFor(fc),
			tail:     t.Tail,
			dryRun:   dryRun,
		})
	}
	return *s
}

type Scanner struct {
	Filename string
	engine   Handler // rule engine scoped to this file source
	tail     func(context.Context, chan string)
	dryRun   bool
}

type Scanners []*Scanner

func (s *Scanners) Scan(ctx context.Context) <-chan *Context {
	ch := make(chan *Context)
	wg := new(sync.WaitGroup)

	for _, s := range *s {
		wg.Add(1)
		go func(s *Scanner) {
			defer wg.Done()
			lines := make(chan string)
			go s.tail(ctx, lines)

			for {
				select {
				case <-ctx.Done():
					return
				case l, ok := <-lines:
					if !ok {
						return
					}
					ch <- &Context{
						Filename: s.Filename,
						Line:     l,
						DryRun:   s.dryRun,
						Started:  time.Now(),
						Engine:   s.engine,
					}
				}
			}
		}(s)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	return ch
}
