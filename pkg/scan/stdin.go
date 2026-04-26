package scan

import (
	"bufio"
	"context"
	"os"
)

func FromStdin(dryRun bool, engine Handler) Scanners {
	return Scanners{
		&Scanner{
			Filename: "stdin",
			engine:   engine,
			tail:     scanStdin,
			dryRun:   dryRun,
		},
	}
}

func scanStdin(ctx context.Context, ch chan string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		case ch <- scanner.Text():
		}
	}
	close(ch)
}
