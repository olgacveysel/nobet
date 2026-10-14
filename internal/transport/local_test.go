//go:build linux

package transport

import (
	"strings"
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
}
