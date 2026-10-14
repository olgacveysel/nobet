package drift

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/store"
)

func facts() *collect.Facts {
	return &collect.Facts{
		IsRoot:     true,
		SSHD:       map[string][]string{"permitrootlogin": {"no"}, "passwordauthentication": {"no"}},
		Passwd:     []collect.PasswdEntry{{Name: "root", UID: 0, Shell: "/bin/bash"}, {Name: "deploy", UID: 1000, GID: 1000, Shell: "/bin/bash"}},
		Groups:     []collect.GroupEntry{},
		SudoRights: map[string][]collect.SudoEntry{},
		AuthKeys:   []collect.AuthKey{{User: "deploy", Fingerprint: "SHA256:aaa", Comment: "ci"}},
		Listeners:  []collect.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 22}},
		Updates:    &collect.Updates{Manager: "apt", Security: []collect.SecurityUpdate{{Package: "openssl"}}},
		Reboot:     &collect.Reboot{Running: "6.1.0-17-amd64"},
	}
}

func TestCompare(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	old := store.HostSnapshot{Host: "web01", Time: t0, Facts: facts(),
		Findings: []checks.Finding{{CheckID: "UPD-001", Title: "1 pending security update(s)"}}}

	nf := facts()
	nf.SSHD["passwordauthentication"] = []string{"yes"}
	nf.SudoRights["deploy"] = []collect.SudoEntry{{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}}
	nf.AuthKeys = append(nf.AuthKeys, collect.AuthKey{User: "deploy", Fingerprint: "SHA256:bbb", Comment: "unknown@laptop"})
	nf.Listeners = append(nf.Listeners, collect.Listener{Proto: "tcp", Addr: "::", Port: 6379})
	nf.Updates.Security = nil
	nf.Reboot.Running = "6.1.0-18-amd64"
	cur := store.HostSnapshot{Host: "web01", Time: t0.Add(24 * time.Hour), Facts: nf,
		Findings: []checks.Finding{{CheckID: "SSH-002", Title: "SSH password authentication is enabled"}}}

	d := Compare(old, cur)
	want := []string{
		"added root deploy via sudo ALL, no password",
		"added key deploy: SHA256:bbb unknown@laptop",
		"changed sshd passwordauthentication: no → yes",
		"added port tcp [::]:6379",
		"added finding SSH-002 SSH password authentication is enabled",
		"removed finding UPD-001 1 pending security update(s)",
		"changed updates pending security updates: 1 → 0",
		"changed kernel running kernel: 6.1.0-17-amd64 → 6.1.0-18-amd64",
	}
	var got []string
	for _, c := range d.Changes {
		got = append(got, c.Kind+" "+c.Area+" "+c.What)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("changes:\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}

	var buf bytes.Buffer
	WriteText(&buf, []HostDrift{d})
	if !strings.Contains(buf.String(), "+  key") && !strings.Contains(buf.String(), "+") {
		t.Errorf("text output:\n%s", buf.String())
	}
	if n, h := Count([]HostDrift{d}); n != len(want) || h != 1 {
		t.Errorf("Count = %d, %d", n, h)
	}
}

func TestCompareUnprivilegedSkipsRootAndKeys(t *testing.T) {
	a, b := facts(), facts()
	a.IsRoot, b.IsRoot = false, false
	b.AuthKeys = nil
	d := Compare(store.HostSnapshot{Facts: a}, store.HostSnapshot{Facts: b})
	for _, c := range d.Changes {
		if c.Area == "root" || c.Area == "key" {
			t.Errorf("unexpected %s change without privilege: %+v", c.Area, c)
		}
	}
}

func TestComparePasswordStates(t *testing.T) {
	old := store.HostSnapshot{Host: "h", Facts: &collect.Facts{Shadow: []collect.ShadowEntry{
		{User: "alice", Password: collect.PasswordLocked}, {User: "bob", Password: collect.PasswordSet}}}}
	cur := store.HostSnapshot{Host: "h", Facts: &collect.Facts{Shadow: []collect.ShadowEntry{
		{User: "alice", Password: collect.PasswordEmpty}, {User: "bob", Password: collect.PasswordSet, Expired: true},
		{User: "carol", Password: collect.PasswordSet}}}}
	d := Compare(old, cur)
	var got []string
	for _, c := range d.Changes {
		got = append(got, c.What)
	}
	want := []string{"alice password: locked → empty", "bob expired: false → true"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCompareGroupsAndApk(t *testing.T) {
	old := store.HostSnapshot{Host: "h", Facts: &collect.Facts{
		Groups:  []collect.GroupEntry{{Name: "sudo", Members: []string{"alice"}}, {Name: "docker"}},
		Updates: &collect.Updates{Manager: "apk", Pending: []string{"musl"}},
	}}
	cur := store.HostSnapshot{Host: "h", Facts: &collect.Facts{
		Groups:  []collect.GroupEntry{{Name: "sudo", Members: []string{"alice", "plain"}}, {Name: "docker", Members: []string{"ci"}}},
		Updates: &collect.Updates{Manager: "apk", Pending: []string{"musl", "busybox", "openssl"}},
	}}
	var got []string
	for _, c := range Compare(old, cur).Changes {
		got = append(got, c.Kind+" "+c.Area+" "+c.What)
	}
	want := []string{"added group ci in docker", "added group plain in sudo", "changed updates pending updates: 1 → 3"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("got %q, want %q", got, want)
	}
}
