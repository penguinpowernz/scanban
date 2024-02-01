package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"syscall"
	"time"
)

// Tailer tails a file, it will also check if the file inode has changed which
// indicates the underlying file was deleted or rotated without using copytrunc
type Tailer struct {
	fn  string
	ino uint64
	r   *bufio.Reader
}

// NewTailer returns a new tailer, with the option to specify if it should tail
// the entire file or only the new lines that are added to the file
func NewTailer(fn string, newLinesOnly bool) (*Tailer, error) {
	t := &Tailer{
		fn: fn,
	}

	return t, t.open(newLinesOnly)
}

func (t *Tailer) open(newLinesOnly bool) error {
	f, err := os.Open(t.fn)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if newLinesOnly {
		f.Seek(0, 2)
	}
	t.r = bufio.NewReader(f)
	t.ino = uint64(fi.Sys().(*syscall.Stat_t).Ino)
	return nil
}

func (t *Tailer) hasInodeChanged() bool {
	fi, err := os.Stat(t.fn)
	if err != nil {
		return false
	}
	if t.ino == uint64(fi.Sys().(*syscall.Stat_t).Ino) {
		return false
	}
	return true
}

func (t *Tailer) Tail(ctx context.Context, lines chan string) {
	for {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 5):
				// check if the file was deleted out from under us
				if !t.hasInodeChanged() {
					continue
				}

				// reopen the file
				if err := t.open(false); err != nil {
					log.Printf("failed to reopen %s: %s", t.fn, err)
					return
				}
			default:
				t.readLine(lines)
			}
		}
	}
}

func (t *Tailer) readLine(lines chan string) {
	line, err := t.r.ReadString('\n')
	if err == io.EOF {
		time.Sleep(time.Second)
		return
	}
	if err != nil {
		return
	}
	if line == "" {
		return
	}
	lines <- line
}
