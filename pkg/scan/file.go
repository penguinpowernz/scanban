package scan

import (
	"bufio"
	"context"
	"os"
)

func FromFile(filename string, dryRun bool) Scanners {
	return Scanners{
		&Scanner{
			Filename: filename,
			tail:     scanFile(filename),
			dryRun:   dryRun,
		},
	}
}

func scanFile(filename string) func(ctx context.Context, ch chan string) {
	return func(ctx context.Context, ch chan string) {
		f, err := os.Open(filename)
		if err != nil {
			close(ch)
			return
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ch <- scanner.Text()
			// log.Println("scanned")
		}
		// log.Println("file scanner for", filename, "done")
		close(ch)
		// log.Println("file scanner for", filename, "exited")
	}
}
