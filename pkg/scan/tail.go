package scan

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"time"
)

var scanAll bool

type tailer interface {
	Tail(ctx context.Context, lines chan string)
}

func NewTailerFromFileConfig(path string) (tailer, error) {
	var t tailer
	var err error

	switch {
	case strings.HasPrefix(path, "docker://"):
		t, err = NewDockerTailer(path, !scanAll)
		if err != nil {
			log.Printf("failed to open %s: %s", path, err)
			return nil, err
		}
	case path != "":
		t, err = NewTailer(path, !scanAll)
		if err != nil {
			log.Printf("failed to open %s: %s", path, err)
			return nil, err
		}
	default:
		log.Printf("failed to open tail: no path or docker specified in config")
		return nil, err
	}

	return t, nil
}

// Tailer tails a file, it will also check if the file inode has changed which
// indicates the underlying file was deleted or rotated without using copytrunc
type Tailer struct {
	fn  string
	ino uint64
	f   *os.File
	r   *bufio.Reader
}

// NewTailer returns a new tailer, with the option to specify if it should tail
// the entire file or only the new lines that are added to the file
func NewTailer(fn string, newLinesOnly bool) (*Tailer, error) {
	t := &Tailer{fn: fn}
	return t, t.open(newLinesOnly)
}

func (t *Tailer) open(newLinesOnly bool) error {
	// Close any previously open file to avoid fd leak on rotation
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}

	f, err := os.Open(t.fn)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if newLinesOnly {
		f.Seek(0, io.SeekEnd)
	}
	t.f = f
	t.r = bufio.NewReader(f)
	t.ino = uint64(fi.Sys().(*syscall.Stat_t).Ino)
	return nil
}

func (t *Tailer) hasInodeChanged() bool {
	fi, err := os.Stat(t.fn)
	if err != nil {
		return false
	}
	return t.ino != uint64(fi.Sys().(*syscall.Stat_t).Ino)
}

// Tail reads new lines from the file and sends them to lines.
// It checks for log rotation every 5 seconds via a ticker rather than
// a tight spin, avoiding both the CPU-spin and the fd-leak on rotation.
func (t *Tailer) Tail(ctx context.Context, lines chan string) {
	defer func() {
		if t.f != nil {
			t.f.Close()
		}
	}()

	rotateTicker := time.NewTicker(5 * time.Second)
	defer rotateTicker.Stop()

	for {
		// Drain all available lines before checking for rotation/ctx
		for {
			line, err := t.r.ReadString('\n')
			if line != "" {
				lines <- strings.TrimRight(line, "\n")
			}
			if err == io.EOF {
				break // no more data right now
			}
			if err != nil {
				log.Printf("error reading %s: %s", t.fn, err)
				return
			}
		}

		// Wait for new data, rotation, or shutdown
		select {
		case <-ctx.Done():
			return
		case <-rotateTicker.C:
			if t.hasInodeChanged() {
				if err := t.open(false); err != nil {
					log.Printf("failed to reopen %s: %s", t.fn, err)
					return
				}
			}
		case <-time.After(time.Second):
			// brief sleep so we don't busy-poll on EOF
		}
	}
}
