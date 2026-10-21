//go:build linux

package transport

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalRun(t *testing.T) {
	l, err := NewLocal(5 * time.Second)
	if err != nil {
		t.Fatal(err)
	}

	res, err := l.Run("echo hello; echo oops >&2; exit 3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(res.Stdout) != "hello" || strings.TrimSpace(res.Stderr) != "oops" || res.ExitCode != 3 {
		t.Errorf("got %+v", res)
	}
}

func TestLocalTimeout(t *testing.T) {
	l, _ := NewLocal(100 * time.Millisecond)
	if _, err := l.Run("sleep 5"); err == nil {
		t.Error("expected a timeout error")
	}

	// A timeout stops what the shell started, too.
	pidFile := t.TempDir() + "/pid"
	l, _ = NewLocal(300 * time.Millisecond)
	if _, err := l.Run("sleep 30 & echo $! > " + pidFile + "; wait"); err == nil {
		t.Fatal("expected a timeout error")
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	time.Sleep(100 * time.Millisecond)
	if pid > 0 && syscall.Kill(pid, 0) == nil {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Error("the child of a timed-out command is still running")
	}
}

func TestLocalNoTerminal(t *testing.T) {
	l, _ := NewLocal(5 * time.Second)
	res, err := l.Run("if (exec 3</dev/tty) 2>/dev/null; then echo tty; else echo none; fi")
	if err != nil || strings.TrimSpace(res.Stdout) != "none" {
		t.Errorf("commands must have no controlling terminal: %+v %v", res, err)
	}
}
