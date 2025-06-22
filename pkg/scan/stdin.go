package scan

import (
	"bufio"
	"context"
	"os"
)

func FromStdin(dryRun bool) Scanners {
	return Scanners{
		&Scanner{
			Filename: "stdin",
			tail:     scanStdin,
			dryRun:   dryRun,
		},
	}
}

func scanStdin(ctx context.Context, ch chan string) {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		ch <- scanner.Text()
	}
	close(ch)
}
