//go:build !unix

package transport

import "os/exec"

// detach does nothing: local scanning only runs on Linux.
func detach(*exec.Cmd) {}
