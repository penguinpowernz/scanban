package scan

import (
	"bufio"
	"context"
	"io"
	"os/exec"
	"strings"
	"time"
)

type DockerTailer struct {
	r    *bufio.Reader
	name string
	cmd  *exec.Cmd
}

func NewDockerTailer(name string, newLinesOnly bool) (*DockerTailer, error) {
	name = strings.TrimPrefix(name, "docker://")
	t := &DockerTailer{
		name: name,
	}

	return t, t.open(newLinesOnly)
}

func (t *DockerTailer) open(newLinesOnly bool) error {
	args := []string{
		"container",
		"logs",
		"-f",
	}

	if newLinesOnly {
		args = append(args, "--tail=0")
	}

	args = append(args, t.name)

	t.cmd = exec.Command("docker", args...)
	rc, err := t.cmd.StdoutPipe()
	if err != nil {
		return err
	}

	t.r = bufio.NewReader(rc)

	return t.cmd.Start()
}

func (t *DockerTailer) Tail(ctx context.Context, lines chan string) {
	defer t.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			t.readLine(lines)
		}
	}
}

func (t *DockerTailer) Close() {
	if t.cmd.Process == nil {
		return
	}
	t.cmd.Process.Kill()
	t.cmd.Wait() // need to reap the PID
}

func (t *DockerTailer) readLine(lines chan string) {
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
