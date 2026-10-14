package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"github.com/olgacveysel/nobet/internal/runner"
)

// Local runs commands on this machine through /bin/sh.
type Local struct {
	timeout time.Duration
}

// NewLocal returns a runner for the local machine. Local scanning is only
// supported on Linux, since every check targets Linux.
func NewLocal(timeout time.Duration) (*Local, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("local scanning is only supported on Linux (this is %s); scan Linux hosts over SSH instead", runtime.GOOS)
	}
	return &Local{timeout: timeout}, nil
}

// Run executes cmd with /bin/sh -c. Stdin is empty, so nothing can prompt.
func (l *Local) Run(cmd string) (runner.Result, error) {
	ctx := context.Background()
	if l.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.timeout)
		defer cancel()
	}

	c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	// If a timed-out command left children holding our pipes open, stop
	// waiting for them shortly after the kill instead of hanging.
	c.WaitDelay = time.Second
	err := c.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return runner.Result{}, fmt.Errorf("command timed out after %s", l.timeout)
	}
	res := runner.Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			return res, nil
		}
		return res, err
	}
	return res, nil
}
