package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestHostBasedLogin(t *testing.T) {
	trust := []collect.HostTrust{
		{File: "/etc/ssh/shosts.equiv", Host: "172.31.10.20"},
		{File: "/etc/ssh/shosts.equiv", Host: "hb-cli"}, // a name: only with UseDNS yes
		{File: "/etc/hosts.equiv", Host: "10.0.0.9", User: "bob"},
		{File: "/root/.shosts", Account: "root", Host: "172.31.10.20", User: "root"},
		{File: "/home/alice/.rhosts", Account: "alice", Host: "10.0.0.7", User: "alice"},
	}
	run := func(sshd map[string][]string) []Finding {
		t.Helper()
		got, skip := hostBasedLogin.Run(&collect.Facts{IsRoot: true, Errors: map[string]string{}, SSHD: sshd, HostTrust: trust})
		if skip != "" {
			t.Fatal(skip)
		}
		return got
	}
	// Off (OpenSSH's default): the files do nothing.
	if got := run(map[string][]string{"hostbasedauthentication": {"no"}, "ignorerhosts": {"yes"}}); len(got) != 0 {
		t.Errorf("host-based off: %+v", got)
	}
	// On, IgnoreRhosts yes: only the equiv files, and only addresses.
	got := run(map[string][]string{"hostbasedauthentication": {"yes"}, "ignorerhosts": {"yes"}, "usedns": {"no"}, "permitrootlogin": {"prohibit-password"}})
	if len(got) != 2 || got[0].Severity != High || !strings.Contains(got[0].Title, "as any account but root") || !strings.Contains(got[0].Detail, "bob@10.0.0.9") ||
		got[1].Severity != Medium || !strings.Contains(got[1].Detail, "172.31.10.20") || strings.Contains(got[1].Detail, "hb-cli") {
		t.Errorf("on, IgnoreRhosts yes: %+v", got)
	}
	// IgnoreRhosts no: root's and alice's own files too; UseDNS yes: names.
	got = run(map[string][]string{"hostbasedauthentication": {"yes"}, "ignorerhosts": {"no"}, "usedns": {"yes"}, "permitrootlogin": {"prohibit-password"}})
	if len(got) != 3 || got[0].Title != "root can log in over SSH from other hosts without a key or password" ||
		!strings.Contains(got[2].Detail, "hb-cli") || !strings.Contains(got[2].Detail, "alice from alice@10.0.0.7") {
		t.Errorf("on, IgnoreRhosts no: %+v", got)
	}
	// PermitRootLogin no keeps root out.
	got = run(map[string][]string{"hostbasedauthentication": {"yes"}, "ignorerhosts": {"no"}, "permitrootlogin": {"no"}})
	if len(got) == 0 || strings.HasPrefix(got[0].Title, "root") {
		t.Errorf("PermitRootLogin no: %+v", got)
	}
	if _, skip := hostBasedLogin.Run(&collect.Facts{IsRoot: true, Errors: map[string]string{"sshd": "x"}, HostTrust: trust}); !strings.Contains(skip, "unavailable") {
		t.Errorf("unknown sshd config: %q", skip)
	}
}
