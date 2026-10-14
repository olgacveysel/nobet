package transport

import (
	"net"
	"os"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
)

// DefaultAgentPipe is where the Windows OpenSSH ssh-agent service listens.
const DefaultAgentPipe = `\\.\pipe\openssh-ssh-agent`

// dialAgent connects to the ssh-agent named by SSH_AUTH_SOCK, which may be
// a named pipe or a Unix socket path, or else to the Windows OpenSSH agent.
func dialAgent() (net.Conn, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		sock = DefaultAgentPipe
	}
	if strings.HasPrefix(sock, `\\.\pipe\`) {
		timeout := 2 * time.Second
		return winio.DialPipe(sock, &timeout)
	}
	return net.Dial("unix", sock) // AF_UNIX works on Windows 10 and later
}
