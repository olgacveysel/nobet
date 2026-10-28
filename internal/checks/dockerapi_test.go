package checks

import (
	"strconv"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestDockerAPIFindings(t *testing.T) {
	f := &collect.Facts{IsRoot: true, Errors: map[string]string{},
		Listeners: []collect.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 2375}, {Proto: "tcp", Addr: "0.0.0.0", Port: 2376}},
		DockerAPI: []collect.DockerAPI{
			{Hosts: []string{"tcp://0.0.0.0:2375"}},
			{Hosts: []string{"tcp://0.0.0.0:2376"}, TLS: true},
			{Hosts: []string{"tcp://127.0.0.1:2377"}},
			{Hosts: []string{"tcp://0.0.0.0:2378"}, TLS: true, Verify: true}, // client certificates: fine
		}}
	got, skip := exposedListeners.Run(f)
	want := []struct {
		sev   Severity
		title string
	}{
		{Critical, "Docker API without TLS is reachable from the network"},
		{Critical, "Docker API accepts clients without a certificate from the network"},
		{High, "Docker API without TLS is reachable from every local account"},
	}
	if skip != "" || len(got) != len(want) {
		t.Fatalf("got %d findings (skip %q): %+v", len(got), skip, got)
	}
	for i, w := range want {
		if got[i].Severity != w.sev || got[i].Title != w.title {
			t.Errorf("finding %d: %v %q, want %v %q", i, got[i].Severity, got[i].Title, w.sev, w.title)
		}
	}
	if !strings.Contains(got[1].Detail, "tlsverify=false") || !strings.Contains(got[1].Fix, "--tlscacert") {
		t.Errorf("TLS finding: %+v", got[1])
	}
	// Without dockerd's settings (an unprivileged scan), the listener on
	// 2375 still counts.
	f.DockerAPI = nil
	if got, _ := exposedListeners.Run(f); len(got) == 0 || got[0].Title != "Docker API without TLS is reachable from the network" {
		t.Errorf("listener only: %+v", got)
	}
}

func TestDockerHost(t *testing.T) {
	for h, want := range map[string]string{
		"tcp://0.0.0.0:2376": "0.0.0.0 2376", "tcp://:2375": " 2375", "tcp://127.0.0.1": "127.0.0.1 2375",
		"tcp://[::1]:2380": "::1 2380", "tcp://localhost:2375/": "localhost 2375",
	} {
		a, p := dockerHost(h, false)
		if got := a + " " + strconv.Itoa(p); got != want {
			t.Errorf("%s: %q, want %q", h, got, want)
		}
	}
	if _, p := dockerHost("tcp://10.0.0.1", true); p != 2376 {
		t.Errorf("TLS default port: %d", p)
	}
}
