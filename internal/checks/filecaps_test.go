package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestFileCaps(t *testing.T) {
	f := &collect.Facts{IsRoot: true, Errors: map[string]string{}, FileCaps: []collect.FileCap{
		// Shipped by RHEL-family distros: packaged, not a shell.
		{Path: "/usr/bin/newuidmap", Owner: "pkg", Caps: "cap_setuid=ep"},
		{Path: "/usr/bin/newgidmap", Owner: "pkg", Caps: "cap_setgid=ep"},
		{Path: "/usr/bin/ping", Owner: "pkg", Caps: "= cap_net_admin,cap_net_raw+p"},
		{Path: "/usr/bin/arping", Owner: "none", Caps: "cap_net_raw=p"},
		// Permitted alone is enough: python raises it with capset.
		{Path: "/usr/bin/python3.12", Owner: "pkg", Caps: "cap_setuid=p"},
		{Path: "/usr/local/bin/node", Owner: "none", Caps: "=ep"},
		{Path: "/usr/bin/tar", Owner: "pkg", Caps: "cap_dac_read_search=ep"},
		{Path: "/home/bob/tool", Owner: "none", Caps: "cap_dac_override=ep"},
		{Path: "/opt/agent/bin/agent", Owner: "none", Caps: "cap_net_raw,cap_sys_ptrace=ep"},
		// A namespaced capability does nothing on the host.
		{Path: "/usr/local/bin/perl", Owner: "none", Caps: "cap_setuid=ep", RootID: 1000},
		// Inheritable only: not the caller's to use.
		{Path: "/usr/bin/vim.basic", Owner: "pkg", Caps: "cap_setuid=i"},
	}}
	got, skip := fileCaps.Run(f)
	if skip != "" || len(got) != 4 {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	want := []struct {
		sev    Severity
		has    []string
		hasnot []string
	}{
		{Critical, []string{"python3.12 (cap_setuid)", "node (cap_setuid,cap_sys_admin"}, []string{"perl", "vim"}},
		{High, []string{"/usr/bin/tar (cap_dac_read_search)"}, nil},
		{High, []string{"/home/bob/tool (cap_dac_override)"}, nil},
		{Medium, []string{"/opt/agent/bin/agent (cap_sys_ptrace)"}, []string{"newuidmap", "arping", "ping"}},
	}
	for i, w := range want {
		if got[i].Severity != w.sev {
			t.Errorf("finding %d severity %v: %+v", i, got[i].Severity, got[i])
		}
		for _, s := range w.has {
			if !strings.Contains(got[i].Detail, s) {
				t.Errorf("finding %d lacks %q: %s", i, s, got[i].Detail)
			}
		}
		for _, s := range w.hasnot {
			if strings.Contains(got[i].Detail, s) {
				t.Errorf("finding %d has %q: %s", i, s, got[i].Detail)
			}
		}
	}
	if _, skip := fileCaps.Run(&collect.Facts{IsRoot: true, Errors: map[string]string{"filecaps": "getcap is not installed"}}); !strings.Contains(skip, "getcap") {
		t.Errorf("no getcap: %q", skip)
	}
}
