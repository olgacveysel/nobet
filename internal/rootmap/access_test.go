package rootmap

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func accessFacts(sshd map[string][]string) *collect.Facts {
	return &collect.Facts{
		SSHD: sshd,
		Passwd: []collect.PasswdEntry{
			{Name: "root", UID: 0, GID: 0},
			{Name: "alice", UID: 1000, GID: 1000},
			{Name: "bob", UID: 1001, GID: 1001},
		},
		Groups: []collect.GroupEntry{
			{Name: "root", GID: 0},
			{Name: "alice", GID: 1000},
			{Name: "bob", GID: 1001},
			{Name: "sshusers", GID: 2000, Members: []string{"alice"}},
		},
		RootWritable: []collect.WritablePath{},
	}
}

func TestLoginAllowed(t *testing.T) {
	cases := []struct {
		sshd map[string][]string
		want map[string]bool
	}{
		{nil, map[string]bool{"root": true, "alice": true, "bob": true}},
		{map[string][]string{"allowusers": {"alice", "root@10.0.0.*"}}, map[string]bool{"root": true, "alice": true, "bob": false}},
		{map[string][]string{"allowusers": {"al* b?b"}}, map[string]bool{"root": false, "alice": true, "bob": true}},
		{map[string][]string{"denyusers": {"root"}}, map[string]bool{"root": false, "alice": true}},
		{map[string][]string{"denyusers": {"root@203.0.113.9"}}, map[string]bool{"root": true}},
		{map[string][]string{"allowgroups": {"sshusers"}}, map[string]bool{"root": false, "alice": true, "bob": false}},
		{map[string][]string{"denygroups": {"bob"}}, map[string]bool{"alice": true, "bob": false}}, // primary group
		{map[string][]string{"allowusers": {"alice", "bob"}, "denyusers": {"bob"}}, map[string]bool{"alice": true, "bob": false}},
	}
	for _, c := range cases {
		f := accessFacts(c.sshd)
		for user, want := range c.want {
			if got := f.LoginAllowed(c.sshd, user); got != want {
				t.Errorf("sshd %v: LoginAllowed(%s) = %v, want %v", c.sshd, user, got, want)
			}
		}
	}
}

func TestBuildRespectsSSHAccess(t *testing.T) {
	f := accessFacts(map[string][]string{
		"permitrootlogin":       {"prohibit-password"},
		"allowusers":            {"alice"},
		"authorizedkeyscommand": {"/usr/bin/sss_ssh_authorizedkeys %u"},
	})
	f.SudoRights = map[string][]collect.SudoEntry{
		"alice": {{RunAs: "ALL", Commands: []string{"ALL"}}},
		"bob":   {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}},
	}
	f.AuthKeys = []collect.AuthKey{
		{User: "root", Fingerprint: "SHA256:root", Type: "ssh-ed25519"},
		{User: "alice", Fingerprint: "SHA256:alice", Type: "ssh-ed25519"},
		{User: "bob", Fingerprint: "SHA256:bob", Type: "ssh-ed25519"},
	}
	m := Build([]scan.HostResult{host("h1", f)})

	if len(m.Keys) != 1 || m.Keys[0].Fingerprint != "SHA256:alice" {
		t.Errorf("only alice may log in, got keys %+v", m.Keys)
	}
	// bob has a key and sudo but AllowUsers keeps him out; root has no
	// route at all because AllowUsers excludes it.
	if len(m.KeylessUsers) != 1 || m.KeylessUsers[0].User != "bob" {
		t.Errorf("keyless: %+v", m.KeylessUsers)
	}
	if len(m.Gaps) != 1 || !strings.Contains(m.Gaps[0].Reason, "AuthorizedKeysCommand") {
		t.Errorf("gaps: %+v", m.Gaps)
	}

	f.SSHD = map[string][]string{"pubkeyauthentication": {"no"}, "permitrootlogin": {"yes"}, "passwordauthentication": {"yes"}}
	routes, _ := Routes(f)
	if rs := routes["root"]; len(rs) != 1 || !rs[0].NeedsPassword {
		t.Errorf("with pubkey off root should only have the password route: %+v", rs)
	}
}

func TestUserGroups(t *testing.T) {
	f := accessFacts(nil)
	if got := strings.Join(f.UserGroups("alice"), ","); got != "alice,sshusers" {
		t.Errorf("alice: %s", got)
	}
	if got := f.UserGroups("nobody"); len(got) != 0 {
		t.Errorf("unknown user: %v", got)
	}
}

func TestRoutesWithMatchBlocks(t *testing.T) {
	// PermitRootLogin no globally, prohibit-password from 10.0.0.0/8; bob
	// may log in only from there.
	f := accessFacts(map[string][]string{"permitrootlogin": {"no"}, "allowusers": {"alice"}})
	f.SSHDMatch = []collect.SSHDContext{
		{User: "root", Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{
			"permitrootlogin": {"prohibit-password"}, "allowusers": {"alice root"}}},
		{User: "root"},
		{User: "bob", Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{"allowusers": {"alice bob"}}},
		{User: "bob"},
	}
	f.SudoRights = map[string][]collect.SudoEntry{"bob": {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}}}
	f.AuthKeys = []collect.AuthKey{
		{User: "root", Fingerprint: "SHA256:root", Type: "ssh-ed25519"},
		{User: "bob", Fingerprint: "SHA256:bob", Type: "ssh-ed25519", Options: []string{"restrict"}},
	}
	m := Build([]scan.HostResult{host("h1", f)})
	if len(m.Keys) != 2 {
		t.Fatalf("keys: %+v", m.Keys)
	}
	for _, k := range m.Keys {
		g := k.Grants[0]
		switch g.User {
		case "root":
			if g.Routes[0].Via != "UID 0 login from 10.0.0.0/8" || g.Restricted != "" {
				t.Errorf("root: %+v", g)
			}
		case "bob":
			if g.Restricted != "restrict, sshd allows it only from 10.0.0.0/8" {
				t.Errorf("bob: %+v", g)
			}
		}
	}
}

func TestRoutesWithPasswordStates(t *testing.T) {
	f := accessFacts(map[string][]string{"permitrootlogin": {"yes"}, "passwordauthentication": {"yes"}})
	f.SudoRights = map[string][]collect.SudoEntry{
		"alice": {{RunAs: "ALL", Commands: []string{"ALL"}}},
		"bob":   {{RunAs: "ALL", Commands: []string{"ALL"}}},
	}
	f.Shadow = []collect.ShadowEntry{
		{User: "root", Password: collect.PasswordLocked},
		{User: "alice", Password: collect.PasswordLocked},
		{User: "bob", Password: collect.PasswordEmpty},
	}
	routes, gaps := Routes(f)
	if rs := routes["root"]; len(rs) != 1 || rs[0].Via != "UID 0 login" {
		t.Errorf("locked root keeps only key login: %+v", rs)
	}
	if rs := routes["alice"]; len(rs) != 0 {
		t.Errorf("locked alice cannot answer sudo's prompt: %+v", rs)
	}
	if rs := routes["bob"]; len(rs) != 1 || rs[0].Via != "sudo ALL, empty password" || rs[0].NeedsPassword {
		t.Errorf("bob: %+v", rs)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps: %v", gaps)
	}

	f.Shadow = []collect.ShadowEntry{{User: "root", Password: collect.PasswordSet, Expired: true}}
	if routes, _ := Routes(f); len(routes["root"]) != 0 {
		t.Errorf("expired root: %+v", routes["root"])
	}
}

func TestRoutesThroughWritableFiles(t *testing.T) {
	f := accessFacts(map[string][]string{"permitrootlogin": {"no"}})
	f.IsRoot = true
	f.SudoRights = map[string][]collect.SudoEntry{}
	f.Passwd = append(f.Passwd, collect.PasswdEntry{Name: "www-data", UID: 33, GID: 33, Shell: "/usr/sbin/nologin"})
	f.Passwd[1].Shell, f.Passwd[2].Shell = "/bin/bash", "/bin/bash"
	f.RootWritable = []collect.WritablePath{
		{Kind: "cron", Source: "/etc/cron.d/app", Path: "/opt/app/run.sh", Writers: []collect.Writer{{Account: "alice", Path: "/opt/app", How: "owner"}, {Account: "uid 4242", Path: "/opt/app/run.sh", How: "owner"}}},
		{Kind: "systemd", Source: "web.service", Path: "/var/www/start", Writers: []collect.Writer{{Account: "www-data", Path: "/var/www", How: "owner"}}},
		{Kind: "startup", Source: "root's shell startup files", Path: "/etc/profile.d/x.sh", Writers: []collect.Writer{{Everyone: true, Path: "/etc/profile.d/x.sh", How: "world-writable"}}},
	}
	routes, gaps := Routes(f)
	got := map[string]string{}
	for u, rs := range routes {
		got[u] = routeText(rs)
	}
	want := map[string]string{
		"alice":    "changes /opt/app/run.sh, used by root's cron (/etc/cron.d/app); changes world-writable /etc/profile.d/x.sh, run by root's login shells",
		"bob":      "changes world-writable /etc/profile.d/x.sh, run by root's login shells",
		"www-data": "changes /var/www/start, used by web.service, which runs as root", // a service account: no login, but its service can
	}
	for u, w := range want {
		if got[u] != w {
			t.Errorf("%s: got %q\nwant %q", u, got[u], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("routes for %v, want only %v", got, want)
	}
	for _, g := range gaps {
		if strings.Contains(g, "files root runs") {
			t.Errorf("unexpected gap %q", g)
		}
	}

	f.RootWritable = nil
	f.Errors = map[string]string{"root-jobs": "timeout"}
	if _, gaps := Routes(f); !strings.Contains(strings.Join(gaps, "|"), "files root runs were not checked (timeout)") {
		t.Errorf("gaps = %q", gaps)
	}
}

func TestFileRoutesCapped(t *testing.T) {
	f := accessFacts(nil)
	f.IsRoot = true
	f.SudoRights = map[string][]collect.SudoEntry{}
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
		f.RootWritable = append(f.RootWritable, collect.WritablePath{Kind: "cron", Source: "/etc/crontab", Path: p,
			Writers: []collect.Writer{{Account: "alice", Path: p, How: "owner"}}})
	}
	routes, _ := Routes(f)
	if rs := routes["alice"]; len(rs) != 4 || rs[3].Via != "changes 2 more files root runs (see FS-003)" {
		t.Errorf("got %+v", rs)
	}
}
