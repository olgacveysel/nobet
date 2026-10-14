package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestCannotConnectToHosts keeps the dashboard unable to reach servers: it
// must not link the SSH transport, the fleet scanner, ssh-agent or
// known_hosts handling. A compromised dashboard can then show weaknesses
// but never act on them.
func TestCannotConnectToHosts(t *testing.T) {
	deps := listDeps(t)
	for _, banned := range []string{
		"github.com/olgacveysel/nobet/internal/transport",
		"github.com/olgacveysel/nobet/internal/fleet",
		"golang.org/x/crypto/ssh/agent",
		"golang.org/x/crypto/ssh/knownhosts",
		"os/exec",
	} {
		if deps[banned] {
			t.Errorf("nobet-web must not import %s", banned)
		}
	}
}

func listDeps(t *testing.T) map[string]bool {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("needs the go command")
	}
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	deps := map[string]bool{}
	for _, d := range strings.Fields(string(out)) {
		deps[d] = true
	}
	return deps
}
