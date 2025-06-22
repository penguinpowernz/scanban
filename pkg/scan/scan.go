package scan

import (
	"context"
	"sync"
	"time"
)

func BuildScanners(files []string, dryRun bool) Scanners {
	s := &Scanners{}
	for _, file := range files {
		t, err := NewTailerFromFileConfig(file)
		if err != nil {
			continue
		}
		*s = append(*s, &Scanner{
			Filename: file,
			tail:     t.Tail,
			dryRun:   dryRun,
		})
	}

	return *s
}

type Scanner struct {
	Filename string
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
			// defer log.Println("scanner for", s.Filename, "exited")

			for {
				select {
				case <-ctx.Done():
					return
				case l, ok := <-lines:
					if !ok {
						// log.Println("scanner for", s.Filename, "closed channel")
						return
					}
					ch <- &Context{
						Filename: s.Filename,
						Line:     l,
						DryRun:   s.dryRun,
						Started:  time.Now(),
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
