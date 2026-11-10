package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestPolkitRoot(t *testing.T) {
	rules := []collect.PolkitRule{
		{File: "/etc/polkit-1/rules.d/10-lab.rules", Yes: true, ActionCheck: true, Actions: []string{"org.freedesktop.policykit.exec"}, Users: []string{"alice"}},
		{File: "/etc/polkit-1/rules.d/20-ops.rules", Yes: true, ActionCheck: true, Prefixes: []string{"org.freedesktop.systemd1."}, Groups: []string{"ops"}},
		{File: "/etc/polkit-1/rules.d/99-all.rules", Yes: true},
		// Debian's own: hostname and timezone for systemd-network only.
		{File: "/usr/share/polkit-1/rules.d/systemd-networkd.rules", Yes: true, ActionCheck: true,
			Actions: []string{"org.freedesktop.hostname1.set-hostname", "org.freedesktop.timedate1.set-timezone"}, Users: []string{"systemd-network"}},
	}
	grants := []collect.PKLAGrant{{File: "/etc/polkit-1/localauthority/50-local.d/lab.pkla",
		Identities: []string{"unix-group:devs", "unix-user:bob"}, Actions: []string{"org.freedesktop.systemd1.*"}}}
	f := &collect.Facts{IsRoot: true, Errors: map[string]string{},
		Groups: []collect.GroupEntry{{Name: "ops", GID: 2000, Members: []string{"carol"}}, {Name: "devs", GID: 2001, Members: []string{"dave"}}},
		Polkit: &collect.Polkit{Version: "126", JSRules: true, Rules: rules, Grants: grants}}
	got, skip := polkitRoot.Run(f)
	if skip != "" || len(got) != 3 {
		t.Fatalf("got %d (skip %q): %+v", len(got), skip, got)
	}
	want := []struct {
		sev           Severity
		title, detail string
	}{
		{High, "A polkit rule lets alice become root without a password", "10-lab.rules answers yes, without asking for a password, for: pkexec"},
		{High, "A polkit rule lets group ops (carol) become root without a password", "systemd-run"},
		{Critical, "A polkit rule lets any account become root without a password", "pkexec (run any program as root); start any command"},
	}
	for i, w := range want {
		if got[i].CheckID != "ACC-009" || got[i].Severity != w.sev || got[i].Title != w.title || !strings.Contains(got[i].Detail, w.detail) {
			t.Errorf("finding %d: %v %q %q", i, got[i].Severity, got[i].Title, got[i].Detail)
		}
	}

	// polkit 0.105 ignores the rules and reads the .pkla grant.
	f.Polkit = &collect.Polkit{Version: "0.105-33", PKLA: true, Rules: rules, Grants: grants}
	got, _ = polkitRoot.Run(f)
	if len(got) != 1 || got[0].Title != "A polkit rule lets bob, group devs (dave) become root without a password" || !strings.Contains(got[0].Detail, "lab.pkla") {
		t.Errorf("0.105: %+v", got)
	}
	// Later versions without pkla-compat ignore .pkla files.
	f.Polkit = &collect.Polkit{Version: "126", JSRules: true, Grants: grants}
	if got, _ := polkitRoot.Run(f); len(got) != 0 {
		t.Errorf(".pkla without pkla-compat: %+v", got)
	}
	f.Polkit = &collect.Polkit{}
	if got, skip := polkitRoot.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("no polkit: %+v %q", got, skip)
	}
	if _, skip := polkitRoot.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
}
