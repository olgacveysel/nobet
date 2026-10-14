//go:build !windows

package transport

import (
	"net"
	"os"
)

// dialAgent connects to the ssh-agent named by SSH_AUTH_SOCK. It returns
// nil and no error when no agent is configured.
func dialAgent() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	return net.Dial("unix", sock)
}
