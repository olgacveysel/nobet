package rootmap

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

const fpLaptop = "SHA256:laptop"

func host(name string, f *collect.Facts) scan.HostResult {
	return scan.HostResult{Host: name, Facts: f}
}

func TestBuild(t *testing.T) {
	web := &collect.Facts{
		SSHD:   map[string][]string{"permitrootlogin": {"prohibit-password"}, "passwordauthentication": {"no"}},
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "deploy", UID: 1000, GID: 1000}, {Name: "backup", UID: 1001, GID: 1001}},
		Groups: []collect.GroupEntry{{Name: "docker", GID: 999, Members: []string{"backup"}}},
		SudoRights: map[string][]collect.SudoEntry{
			"root":   {{RunAs: "ALL : ALL", Commands: []string{"ALL"}}},
			"deploy": {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}},
		},
		AuthKeys: []collect.AuthKey{
			{User: "root", Fingerprint: fpLaptop, Type: "ssh-ed25519", Comment: "veysel@laptop"},
			{User: "deploy", Fingerprint: fpLaptop, Type: "ssh-ed25519", Comment: "veysel@laptop"},
		},
		RootWritable: []collect.WritablePath{},
	}
	db := &collect.Facts{
		SSHD:       map[string][]string{"permitrootlogin": {"no"}},
		Passwd:     []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "ops", UID: 1000, GID: 1000}},
		Groups:     []collect.GroupEntry{},
		SudoRights: map[string][]collect.SudoEntry{"ops": {{RunAs: "ALL", Commands: []string{"ALL"}}}},
		AuthKeys: []collect.AuthKey{
			{User: "root", Fingerprint: fpLaptop, Type: "ssh-ed25519"}, // useless: PermitRootLogin no
			{User: "ops", Fingerprint: "SHA256:ci", Type: "ssh-ed25519", Options: []string{`from="10.0.0.5"`}},
		},
		RootWritable: []collect.WritablePath{},
	}

	m := Build([]scan.HostResult{
		host("web01", web),
		host("db01", db),
		{Host: "db02", Error: "connection refused"},
	})

	if len(m.Keys) != 2 {
		t.Fatalf("got %d keys, want 2: %+v", len(m.Keys), m.Keys)
	}
	byFP := map[string]Key{}
	for _, k := range m.Keys {
		byFP[k.Fingerprint] = k
	}
	laptop := byFP[fpLaptop]
	if laptop.Hosts() != 1 || len(laptop.Grants) != 2 {
		t.Errorf("laptop key: %+v", laptop)
	}
	ci := byFP["SHA256:ci"]
	if len(ci.Grants) != 1 || ci.Grants[0].Host != "db01" || !ci.Grants[0].Routes[0].NeedsPassword || ci.Grants[0].Restricted == "" {
		t.Errorf("ci key: %+v", ci)
	}

	// backup has docker group membership but no key.
	if len(m.KeylessUsers) != 1 || m.KeylessUsers[0].User != "backup" {
		t.Errorf("keyless users: %+v", m.KeylessUsers)
	}
	if len(m.Gaps) != 1 || m.Gaps[0].Host != "db02" {
		t.Errorf("gaps: %+v", m.Gaps)
	}

	var buf bytes.Buffer
	m.WriteText(&buf)
	if !strings.Contains(buf.String(), "veysel@laptop") || !strings.Contains(buf.String(), "docker group") {
		t.Errorf("text output missing expected content:\n%s", buf.String())
	}
}

func TestRoutesWithoutSSHD(t *testing.T) {
	f := &collect.Facts{
		SSHD:         map[string][]string{}, // sshd not installed
		Passwd:       []collect.PasswdEntry{{Name: "root", UID: 0}},
		Groups:       []collect.GroupEntry{},
		SudoRights:   map[string][]collect.SudoEntry{},
		RootWritable: []collect.WritablePath{},
	}
	routes, gaps := Routes(f)
	if len(routes) != 0 || len(gaps) != 0 {
		t.Errorf("no sshd: routes %+v, gaps %v; want none", routes, gaps)
	}

	if _, gaps := Routes(&collect.Facts{SSHD: map[string][]string{}, Groups: []collect.GroupEntry{}, SudoRights: map[string][]collect.SudoEntry{}, RootWritable: []collect.WritablePath{}}); len(gaps) != 1 {
		t.Errorf("missing passwd should be a gap, got %v", gaps)
	}
}

func TestSudoRoute(t *testing.T) {
	cases := []struct {
		entries []collect.SudoEntry
		pw      string
		want    string
	}{
		{[]collect.SudoEntry{{RunAs: "root", Commands: []string{"/usr/sbin/reboot"}}}, "", ""},
		{[]collect.SudoEntry{{RunAs: "root", Commands: []string{"/usr/bin/vim"}}}, "", "sudo /usr/bin/vim (shell escape), password required"},
		{[]collect.SudoEntry{
			{RunAs: "ALL", Commands: []string{"ALL"}},
			{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/less"}},
		}, collect.PasswordSet, "sudo /usr/bin/less (shell escape), no password"},
		{[]collect.SudoEntry{
			{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/less"}},
			{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}},
		}, "", "sudo ALL, no password"},
		// A locked password makes rules that ask for it useless...
		{[]collect.SudoEntry{{RunAs: "ALL", Commands: []string{"ALL"}}}, collect.PasswordLocked, ""},
		{[]collect.SudoEntry{
			{RunAs: "ALL", Commands: []string{"ALL"}},
			{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/less"}},
		}, collect.PasswordLocked, "sudo /usr/bin/less (shell escape), no password"},
		// ...and an empty one makes them free.
		{[]collect.SudoEntry{{RunAs: "ALL", Commands: []string{"ALL"}}}, collect.PasswordEmpty, "sudo ALL, empty password"},
	}
	for _, c := range cases {
		r, ok := sudoRoute(c.entries, c.pw, fixedAuth(collect.SudoAuthUser))
		if got := r.Via; !ok && got != "" || got != c.want {
			t.Errorf("%+v: got %q (%v), want %q", c.entries, got, ok, c.want)
		}
		if ok && r.NeedsPassword != strings.Contains(c.want, "password required") {
			t.Errorf("%+v: NeedsPassword = %v", c.entries, r.NeedsPassword)
		}
	}
}

func TestSudoRouteAuth(t *testing.T) {
	all := []collect.SudoEntry{{RunAs: "ALL", Commands: []string{"ALL"}}}
	if r, ok := sudoRoute(all, collect.PasswordSet, fixedAuth(collect.SudoAuthTarget)); ok {
		t.Errorf("targetpw: root's password is no route, got %+v", r)
	}
	if r, _ := sudoRoute(all, collect.PasswordLocked, fixedAuth(collect.SudoAuthNone)); r.Via != "sudo ALL, no password" || r.NeedsPassword {
		t.Errorf("!authenticate: %+v", r)
	}
	nopw := []collect.SudoEntry{{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}}
	if r, _ := sudoRoute(nopw, "", fixedAuth(collect.SudoAuthTarget)); r.Via != "sudo ALL, no password" {
		t.Errorf("NOPASSWD beats targetpw: %+v", r)
	}
}

func fixedAuth(a string) func(string) string { return func(string) string { return a } }

func TestSudoRoutePerCommand(t *testing.T) {
	// targetpw for everything run as root, except less (!authenticate):
	// of vim, less and find only less is a route.
	entries := []collect.SudoEntry{{RunAs: "root", Commands: []string{"/usr/bin/vim", "/usr/bin/less", "/usr/bin/find"}}}
	authFor := func(cmd string) string {
		if cmd == "/usr/bin/less" {
			return collect.SudoAuthNone
		}
		return collect.SudoAuthTarget
	}
	if r, _ := sudoRoute(entries, collect.PasswordSet, authFor); r.Via != "sudo /usr/bin/less (shell escape), no password" {
		t.Errorf("got %+v", r)
	}
}

func TestBuildKeyLogins(t *testing.T) {
	since := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	used := time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)
	f := &collect.Facts{
		SSHD:   map[string][]string{"permitrootlogin": {"prohibit-password"}},
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "deploy", UID: 1000}},
		SudoRights: map[string][]collect.SudoEntry{
			"deploy": {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}},
		},
		AuthKeys: []collect.AuthKey{
			{User: "root", Fingerprint: fpLaptop, Type: "ssh-ed25519"},
			{User: "deploy", Fingerprint: fpLaptop, Type: "ssh-ed25519"},
		},
		KeyLogins:    &collect.KeyLogins{Since: since, Last: map[string]time.Time{"deploy " + fpLaptop: used}},
		RootWritable: []collect.WritablePath{},
	}
	m := Build([]scan.HostResult{host("web01", f), host("db01", &collect.Facts{
		SSHD: f.SSHD, Passwd: f.Passwd, AuthKeys: f.AuthKeys[:1], RootWritable: []collect.WritablePath{}, // logs not read
	})})
	got := map[string]string{}
	for _, g := range m.Keys[0].Grants {
		got[g.Host+" "+g.User] = g.LoginText()
	}
	want := map[string]string{
		"web01 root":   "no login since 2026-06-01",
		"web01 deploy": "last login 2026-10-11",
		"db01 root":    "",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("logins: %v, want %v", got, want)
	}
	var buf bytes.Buffer
	m.WriteText(&buf)
	if !strings.Contains(buf.String(), "(last login 2026-10-11)") || !strings.Contains(buf.String(), "(no login since 2026-06-01)") {
		t.Errorf("text output:\n%s", buf.String())
	}
}
