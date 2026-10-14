package collect

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitSSHD(t *testing.T) {
	out := "port 22\npermitrootlogin no\n@@match\nMatch Address 10.0.0.0/8,192.168.1.*\n  Match User deploy\n"
	cfg, matches := splitSSHD(out)
	if got := parseSSHD(cfg); got["permitrootlogin"][0] != "no" || len(got) != 2 {
		t.Errorf("config: %v", got)
	}
	if len(matches) != 2 || matches[1] != "Match User deploy" {
		t.Errorf("matches: %q", matches)
	}
	if cfg, matches := splitSSHD(""); cfg != "" || matches != nil {
		t.Errorf("no sshd: %q %q", cfg, matches)
	}
}

func TestProbeAddrs(t *testing.T) {
	addrs, from := probeAddrs([]string{
		"Match Address 10.0.0.0/8,192.168.1.*,!172.16.0.0/12",
		"Match User deploy Address 203.0.113.7",
		"match address=2001:db8::/32",
		"Match Address 10.0.0.0/8", // duplicate
		"Match Host *.example.com",
		"Match LocalPort 2222",
	})
	wantAddrs := []string{"10.0.0.1", "192.168.1.1", "203.0.113.7", "2001:db8::1"}
	wantFrom := []string{"10.0.0.0/8", "192.168.1.*", "203.0.113.7", "2001:db8::/32"}
	if !reflect.DeepEqual(addrs, wantAddrs) || !reflect.DeepEqual(from, wantFrom) {
		t.Errorf("got %q %q", addrs, from)
	}
	for _, bad := range []string{"10.*.*.*.*", "fe80::*", "", "!10.0.0.0/8", "host.example.com"} {
		if a, ok := sampleAddr(bad); ok {
			t.Errorf("sampleAddr(%q) = %q, want no address", bad, a)
		}
	}
	if a, _ := sampleAddr("10.*"); a != "10.1.1.1" {
		t.Errorf("sampleAddr(10.*) = %q", a)
	}
}

func TestProbeUsers(t *testing.T) {
	f := &Facts{
		Passwd: []PasswdEntry{{Name: "root", UID: 0}, {Name: "toor", UID: 0}, {Name: "web", UID: 33, GID: 33}},
		Groups: []GroupEntry{{Name: "docker", GID: 999, Members: []string{"ci"}}},
		SudoRights: map[string][]SudoEntry{
			"alice":           {{RunAs: "ALL", Commands: []string{"ALL"}}},
			"bob":             nil, // no rules
			"x;reboot":        {{RunAs: "ALL", Commands: []string{"ALL"}}},
			"$(touch /x)":     {{RunAs: "ALL", Commands: []string{"ALL"}}},
			"nobet-probe":     {{RunAs: "ALL", Commands: []string{"ALL"}}},
			"svc.backup@corp": {{RunAs: "ALL", Commands: []string{"/usr/bin/rsync"}}},
		},
	}
	want := []string{"root", "toor", "alice", "ci", "svc.backup@corp"}
	if got := probeUsers(f); !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	// Whatever ends up in the script must be inert in sh.
	script := sshdMatchScript(probeUsers(f), []string{"10.0.0.1"}, 2222)
	if strings.ContainsAny(strings.Join(probeUsers(f), ""), ";$`()|&<>'\"\\ ") || !strings.Contains(script, "lport=2222") {
		t.Errorf("script:\n%s", script)
	}
}

// Real sshd -T -C output, shortened, from OpenSSH 9.6 with
// "Match Address 10.0.0.0/8 / PermitRootLogin prohibit-password".
const matchOut = `@@ctx nobet-probe 192.0.2.1
port 22
permitrootlogin no
passwordauthentication yes
@@ctx nobet-probe 10.0.0.1
port 22
permitrootlogin without-password
passwordauthentication yes
@@ctx root 192.0.2.1
port 22
permitrootlogin no
passwordauthentication yes
@@ctx root 10.0.0.1
port 22
permitrootlogin without-password
passwordauthentication yes
@@ctx deploy 192.0.2.1
port 22
permitrootlogin no
@@ctx deploy 10.0.0.1
port 22
permitrootlogin without-password
`

func TestParseSSHDMatch(t *testing.T) {
	base := parseSSHD("port 22\npermitrootlogin no\npasswordauthentication yes\n")
	ctxs, err := parseSSHDMatch(matchOut, base, map[string]string{"10.0.0.1": "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ctxs) != 6 {
		t.Fatalf("got %d contexts: %+v", len(ctxs), ctxs)
	}
	if c := ctxs[0]; c.User != "" || c.Addr != "" || c.Changes != nil {
		t.Errorf("baseline context should map to any user, anywhere, no changes: %+v", c)
	}
	if c := ctxs[3]; c.User != "root" || c.From != "10.0.0.0/8" || c.Changes["permitrootlogin"][0] != "without-password" || len(c.Changes) != 1 {
		t.Errorf("root from 10/8: %+v", c)
	}
	if c := ctxs[4]; c.Changes["passwordauthentication"] == nil || len(c.Changes["passwordauthentication"]) != 0 {
		t.Errorf("a setting missing from a context should be recorded as empty: %+v", c)
	}

	f := &Facts{SSHD: base, SSHDMatch: ctxs}
	views := f.SSHDViews("root")
	if len(views) != 2 || SSHDFirst(views[0].Config, "permitrootlogin") != "no" ||
		views[1].From != "10.0.0.0/8" || SSHDFirst(views[1].Config, "permitrootlogin") != "without-password" {
		t.Errorf("root views: %+v", views)
	}
	if v := f.SSHDViews("deploy"); SSHDFirst(v[0].Config, "passwordauthentication") != "" {
		t.Errorf("deploy has no passwordauthentication line in its context: %+v", v[0])
	}
	if v := f.SSHDViews("stranger"); len(v) != 2 || v[0].User != "stranger" || SSHDFirst(v[0].Config, "passwordauthentication") != "yes" {
		t.Errorf("unprobed users fall back to the any-account views: %+v", v)
	}
	if got := f.SSHDUsers(); !reflect.DeepEqual(got, []string{"", "root", "deploy"}) {
		t.Errorf("SSHDUsers = %q", got)
	}

	failed := matchOut + "@@ctx root 10.9.9.9\n'Match RDomain' in configuration but 'rdomain' not in connection test specification.\n@@failed\n"
	if _, err := parseSSHDMatch(failed, base, nil); err == nil || !strings.Contains(err.Error(), "rdomain") {
		t.Errorf("failed evaluation should be reported, got %v", err)
	}
}

func TestSSHDViewsWithoutMatch(t *testing.T) {
	if v := (&Facts{SSHD: map[string][]string{}}).SSHDViews("root"); v != nil {
		t.Errorf("no sshd: %+v", v)
	}
	if v := (&Facts{}).SSHDViews("root"); len(v) != 1 || v[0].Config != nil {
		t.Errorf("unknown config: %+v", v)
	}
	base := map[string][]string{"permitrootlogin": {"no"}}
	if v := (&Facts{SSHD: base}).SSHDViews("root"); len(v) != 1 || SSHDFirst(v[0].Config, "permitrootlogin") != "no" {
		t.Errorf("plain config: %+v", v)
	}
}
