//go:build unix

package transport

import (
	"os/exec"
	"syscall"
)

// detach starts c in a session of its own: with no controlling terminal,
// nothing it runs can prompt on the terminal nobet was started from (sudo,
// or ssh-keygen asking for a passphrase, would otherwise wait there), and a
// timeout kills its whole process group rather than only the shell.
func detach(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
}
