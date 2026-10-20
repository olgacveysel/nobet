package checks

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestGrantsAll(t *testing.T) {
	cases := map[string]bool{
		"deploy ALL=(ALL) NOPASSWD: ALL":              true,
		"backup ALL=(root) NOPASSWD: /usr/bin/rsync":  false,
		"ops ALL=(ALL) NOPASSWD: /bin/systemctl, ALL": true,
		"%admin ALL=(ALL) ALL":                        false,
	}
	for rule, want := range cases {
		if got := grantsAll(rule); got != want {
			t.Errorf("grantsAll(%q) = %v, want %v", rule, got, want)
		}
	}
}

func TestSSHRootLogin(t *testing.T) {
	f := &collect.Facts{SSHD: map[string][]string{"permitrootlogin": {"yes"}}}
	got, skip := sshRootLogin.Run(f)
	if skip != "" || len(got) != 1 || got[0].Severity != High {
		t.Fatalf("got %+v, skip %q; want one High finding", got, skip)
	}

	f.SSHD["permitrootlogin"] = []string{"no"}
	if got, _ := sshRootLogin.Run(f); len(got) != 0 {
		t.Errorf("PermitRootLogin no: got %+v, want no findings", got)
	}

	if _, skip := sshRootLogin.Run(&collect.Facts{}); skip == "" {
		t.Error("missing sshd config should skip the check")
	}
}

func TestSSHDSkipReasons(t *testing.T) {
	cases := []struct {
		f    *collect.Facts
		want string
	}{
		{&collect.Facts{SSHD: map[string][]string{}}, "not installed"},
		{&collect.Facts{}, "needs root"},
		{&collect.Facts{IsRoot: true, Errors: map[string]string{"sshd": "/etc/ssh/sshd_config line 3: Bad option"}}, "Bad option"},
	}
	for _, c := range cases {
		for _, chk := range []Check{sshRootLogin, sshPasswordAuth, sshEmptyPasswords, sshX11Forwarding} {
			got, skip := chk.Run(c.f)
			if len(got) != 0 || !strings.Contains(skip, c.want) {
				t.Errorf("%s with %+v: findings %+v, skip %q; want skip containing %q", chk.ID, c.f, got, skip, c.want)
			}
		}
	}
}

func TestExposedListeners(t *testing.T) {
	f := &collect.Facts{Listeners: []collect.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 3306},
		{Proto: "tcp", Addr: "::", Port: 3306},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 6379},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443},
	}}
	got, _ := exposedListeners.Run(f)
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (MySQL high + other info): %+v", len(got), got)
	}
	if got[0].Severity != High || got[1].Severity != Info {
		t.Errorf("unexpected severities: %+v", got)
	}
}

func TestPendingSecurityUpdates(t *testing.T) {
	f := &collect.Facts{Updates: &collect.Updates{Manager: "dnf", Total: -1, ListsAgeDays: -1,
		Security: []collect.SecurityUpdate{{Package: "openssl", Severity: "important"}}}}
	got, skip := pendingSecurityUpdates.Run(f)
	if skip != "" || len(got) != 1 || got[0].Severity != High {
		t.Fatalf("got %+v, skip %q", got, skip)
	}

	f.Updates = &collect.Updates{Manager: "apt", Total: 0, ListsAgeDays: 0}
	if got, skip := pendingSecurityUpdates.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("no updates: got %+v, skip %q", got, skip)
	}

	f.Updates = &collect.Updates{Manager: "dnf", Err: "dnf query failed with exit status 1"}
	if _, skip := pendingSecurityUpdates.Run(f); skip == "" {
		t.Error("failed query should skip, not pass")
	}
}

func TestRebootRequired(t *testing.T) {
	f := &collect.Facts{Reboot: &collect.Reboot{Running: "5.14.0-427.el9.x86_64", Latest: "5.14.0-503.el9.x86_64"}}
	if got, _ := rebootRequired.Run(f); len(got) != 1 {
		t.Errorf("newer kernel installed: got %+v", got)
	}
	f.Reboot = &collect.Reboot{Running: "6.1.0-18-amd64", Latest: "6.1.0-18-amd64"}
	if got, _ := rebootRequired.Run(f); len(got) != 0 {
		t.Errorf("same kernel: got %+v", got)
	}
	f.Reboot = &collect.Reboot{Running: "6.6.1-arch1-1", Latest: "linux"} // Arch-style unversioned name
	if got, _ := rebootRequired.Run(f); len(got) != 0 {
		t.Errorf("unversioned kernel name should not trigger: got %+v", got)
	}
}

func TestSeverityJSONRoundTrip(t *testing.T) {
	in := []Finding{{CheckID: "SSH-001", Severity: High}, {CheckID: "NET-001", Severity: Info}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []Finding
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out[0].Severity != High || out[1].Severity != Info {
		t.Errorf("round trip: %+v", out)
	}
}

func TestSUIDFiles(t *testing.T) {
	f := &collect.Facts{SUID: []collect.SUIDFile{
		{Path: "/usr/bin/sudo", Owner: "pkg"},
		{Path: "/usr/bin/find", Owner: "pkg"},
		{Path: "/opt/vendor/bin/helper", Owner: "none"},
		{Path: "/tmp/.x", Owner: "none"},
	}}
	got, skip := suidFiles.Run(f)
	if skip != "" || len(got) != 3 {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	if got[0].Severity != Critical || got[1].Severity != High || got[2].Severity != Medium {
		t.Errorf("severities: %+v", got)
	}
	if got, _ := suidFiles.Run(&collect.Facts{SUID: []collect.SUIDFile{{Path: "/usr/bin/passwd", Owner: "pkg"}}}); len(got) != 0 {
		t.Errorf("packaged passwd should be fine: %+v", got)
	}
}

func TestHostFirewall(t *testing.T) {
	f := &collect.Facts{
		Firewall:  &collect.Firewall{UFW: "Status: inactive", IptChecked: true, IptInputPolicy: "ACCEPT"},
		Listeners: []collect.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 22}, {Proto: "tcp", Addr: "0.0.0.0", Port: 8080}},
	}
	got, _ := hostFirewall.Run(f)
	if len(got) != 1 || got[0].Severity != Medium {
		t.Fatalf("inactive firewall with exposed port: %+v", got)
	}
	f.Firewall.UFW = "Status: active"
	if got, _ := hostFirewall.Run(f); len(got) != 0 {
		t.Errorf("active ufw: %+v", got)
	}
}

func TestSudoShellEscape(t *testing.T) {
	f := &collect.Facts{SudoRights: map[string][]collect.SudoEntry{
		"root":   {{RunAs: "ALL", Commands: []string{"ALL"}}},
		"admin":  {{RunAs: "ALL", Commands: []string{"ALL"}}, {RunAs: "root", Commands: []string{"/usr/bin/vim"}}},
		"web":    {{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/systemctl restart nginx", "/usr/bin/journalctl -u nginx"}}},
		"backup": {{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/rsync -a /srv/ /backup/"}}},
	}}
	got, skip := sudoShellEscape.Run(f)
	if skip != "" || len(got) != 1 || got[0].Severity != High || !strings.Contains(got[0].Title, "web") ||
		!strings.Contains(got[0].Detail, "journalctl") || strings.Contains(got[0].Detail, "systemctl") ||
		!strings.Contains(got[0].Detail, "no password") {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	if _, skip := sudoShellEscape.Run(&collect.Facts{}); skip == "" {
		t.Error("missing sudo rights should skip")
	}
}

// matchFacts has global settings that are safe, and Match blocks that
// relax them for 10.0.0.0/8 and for the deploy account.
func matchFacts() *collect.Facts {
	return &collect.Facts{
		IsRoot: true,
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "deploy", UID: 1000, GID: 1000}},
		SSHD: map[string][]string{
			"permitrootlogin": {"no"}, "passwordauthentication": {"no"}, "x11forwarding": {"no"},
		},
		SSHDMatch: []collect.SSHDContext{
			{User: "", Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{"permitrootlogin": {"without-password"}}},
			{User: "root", Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{"permitrootlogin": {"without-password"}}},
			{User: "root"},
			{User: "deploy", Changes: map[string][]string{"passwordauthentication": {"yes"}}},
			{User: "deploy", Addr: "10.0.0.1", From: "10.0.0.0/8", Changes: map[string][]string{"passwordauthentication": {"yes"}, "permitrootlogin": {"without-password"}}},
		},
	}
}

func TestSSHChecksWithMatch(t *testing.T) {
	f := matchFacts()
	got, _ := sshRootLogin.Run(f)
	if len(got) != 1 || got[0].Severity != Low || !strings.Contains(got[0].Detail, "from 10.0.0.0/8") {
		t.Errorf("SSH-001: %+v", got)
	}
	got, _ = sshPasswordAuth.Run(f)
	// deploy has it from anywhere, so its address-specific views add nothing.
	if len(got) != 1 || got[0].Severity != Medium || !strings.HasSuffix(got[0].Detail, "(set by Match blocks: for deploy)") {
		t.Errorf("SSH-002: %+v", got)
	}
	if got, _ := sshX11Forwarding.Run(f); len(got) != 0 {
		t.Errorf("SSH-004: %+v", got)
	}

	// A global setting is reported without qualifiers.
	f.SSHD["permitrootlogin"] = []string{"yes"}
	got, _ = sshRootLogin.Run(f)
	if len(got) != 1 || got[0].Severity != High || got[0].Detail != "PermitRootLogin yes" {
		t.Errorf("global yes: %+v", got)
	}

	// Root shut out by AllowUsers cannot log in at all.
	f.SSHD["allowusers"] = []string{"deploy"}
	if got, _ := sshRootLogin.Run(f); len(got) != 0 {
		t.Errorf("AllowUsers deploy: %+v", got)
	}
}

func TestEmptyPasswords(t *testing.T) {
	f := &collect.Facts{
		Passwd: []collect.PasswdEntry{
			{Name: "root", UID: 0, Shell: "/bin/bash"},
			{Name: "ops", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			{Name: "guest", UID: 1001, GID: 1001, Shell: "/bin/sh"},
			{Name: "svc", UID: 999, GID: 999, Shell: "/usr/sbin/nologin"},
			{Name: "old", UID: 1002, GID: 1002, Shell: "/bin/bash"},
		},
		Groups:     []collect.GroupEntry{},
		SudoRights: map[string][]collect.SudoEntry{"ops": {{RunAs: "ALL", Commands: []string{"ALL"}}}},
		Shadow: []collect.ShadowEntry{
			{User: "root", Password: collect.PasswordSet},
			{User: "ops", Password: collect.PasswordEmpty},
			{User: "guest", Password: collect.PasswordEmpty},
			{User: "svc", Password: collect.PasswordEmpty},
			{User: "old", Password: collect.PasswordEmpty, Expired: true},
		},
	}
	got, skip := emptyPasswords.Run(f)
	if skip != "" || len(got) != 2 {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	if got[0].Severity != Critical || !strings.HasPrefix(got[0].Detail, "ops;") ||
		got[1].Severity != High || !strings.HasPrefix(got[1].Detail, "guest;") {
		t.Errorf("findings: %+v", got)
	}
	if _, skip := emptyPasswords.Run(&collect.Facts{}); skip == "" {
		t.Error("missing shadow data should skip")
	}
}

func TestUpdatesApk(t *testing.T) {
	f := &collect.Facts{Updates: &collect.Updates{Manager: "apk", Total: 2, ListsAgeDays: 1, Pending: []string{"busybox", "musl"}}}
	got, skip := pendingSecurityUpdates.Run(f)
	if skip != "" || len(got) != 1 || got[0].Severity != Medium || !strings.Contains(got[0].Detail, "does not say which") {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	f.Updates = &collect.Updates{Manager: "apk", ListsAgeDays: -1, Err: "apk metadata cache is missing for some repositories"}
	if _, skip := pendingSecurityUpdates.Run(f); !strings.Contains(skip, "apk update") {
		t.Errorf("skip %q should say how to refresh", skip)
	}
}

func TestStaleIndexes(t *testing.T) {
	for _, mgr := range []string{"apt", "dnf", "zypper", "apk"} {
		f := &collect.Facts{Updates: &collect.Updates{Manager: mgr, ListsAgeDays: 30}}
		got, _ := staleUpdateLists.Run(f)
		if len(got) != 1 || !strings.Contains(got[0].Fix, refreshHint[mgr]) {
			t.Errorf("%s: %+v", mgr, got)
		}
	}
	if got, _ := staleUpdateLists.Run(&collect.Facts{Updates: &collect.Updates{Manager: "dnf", ListsAgeDays: 3}}); len(got) != 0 {
		t.Errorf("fresh: %+v", got)
	}
}

func TestSudoTargetPassword(t *testing.T) {
	// openSUSE: "Defaults targetpw" with "ALL ALL=(ALL) ALL".
	f := &collect.Facts{
		Passwd: []collect.PasswdEntry{{Name: "alice", UID: 1000, GID: 1000, Shell: "/bin/bash"}},
		Groups: []collect.GroupEntry{},
		Shadow: []collect.ShadowEntry{{User: "alice", Password: collect.PasswordEmpty}},
		SudoRights: map[string][]collect.SudoEntry{"alice": {
			{RunAs: "ALL", Commands: []string{"ALL"}},
			{RunAs: "root", Commands: []string{"/usr/bin/vim"}},
		}},
		SudoDefaults: map[string]collect.SudoDefaults{"alice": {Flags: map[string]bool{"targetpw": true}}},
	}
	if got, _ := sudoShellEscape.Run(f); len(got) != 0 {
		t.Errorf("ACC-004: rules that need root's password give nothing: %+v", got)
	}
	if got, _ := emptyPasswords.Run(f); len(got) != 1 || got[0].Severity != High {
		t.Errorf("ACC-005: alice cannot become root, so High: %+v", got)
	}

	f.SudoRights["alice"][1].NoPasswd = true // NOPASSWD needs no password at all
	if got, _ := sudoShellEscape.Run(f); len(got) != 1 || !strings.Contains(got[0].Detail, "no password needed") {
		t.Errorf("ACC-004 with NOPASSWD escape: %+v", got)
	}
}

func TestSkipReasonsNameTheCause(t *testing.T) {
	unpriv := &collect.Facts{Errors: map[string]string{}}
	timedOut := &collect.Facts{IsRoot: true, Errors: map[string]string{
		"files": "command timed out after 1m0s", "updates": "command timed out after 1m0s"}}
	if _, skip := suidFiles.Run(unpriv); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
	if _, skip := suidFiles.Run(timedOut); !strings.Contains(skip, "timed out") || strings.Contains(skip, "needs root") {
		t.Errorf("privileged but timed out: %q", skip)
	}
	if _, skip := pendingSecurityUpdates.Run(timedOut); !strings.Contains(skip, "timed out") {
		t.Errorf("updates: %q", skip)
	}
}

func TestSudoShellEscapeLockedPassword(t *testing.T) {
	// plain has sudo ALL behind a locked password, plus a passwordless
	// escape: the escape is the real route and must be reported.
	f := &collect.Facts{
		Shadow: []collect.ShadowEntry{{User: "plain", Password: collect.PasswordLocked}},
		SudoRights: map[string][]collect.SudoEntry{"plain": {
			{RunAs: "ALL : ALL", Commands: []string{"ALL"}},
			{RunAs: "root", NoPasswd: true, Commands: []string{"/usr/bin/less"}},
		}},
	}
	if got, _ := sudoShellEscape.Run(f); len(got) != 1 || !strings.Contains(got[0].Detail, "/usr/bin/less") {
		t.Errorf("got %+v", got)
	}
	f.Shadow[0].Expired = true
	if got, _ := sudoShellEscape.Run(f); len(got) != 0 {
		t.Errorf("expired accounts cannot use sudo: %+v", got)
	}
}

func TestRootWritable(t *testing.T) {
	f := &collect.Facts{IsRoot: true, Errors: map[string]string{}, RootWritable: []collect.WritablePath{
		{Kind: "cron", Source: "/etc/cron.d/app", Path: "/opt/app/run.sh", Writers: []collect.Writer{{Account: "deploy", Path: "/opt/app", How: "owner"}}},
		{Kind: "startup", Source: "root's shell startup files", Path: "/etc/profile.d/x.sh", Writers: []collect.Writer{{Everyone: true, Path: "/etc/profile.d/x.sh", How: "world-writable"}}},
	}}
	got, skip := rootWritable.Run(f)
	if skip != "" || len(got) != 2 {
		t.Fatalf("got %+v, skip %q", got, skip)
	}
	if got[0].Severity != Critical || got[0].Detail != "/etc/profile.d/x.sh run by root's login shells: /etc/profile.d/x.sh is world-writable" {
		t.Errorf("world-writable: %+v", got[0])
	}
	if got[1].Severity != High || got[1].Detail != "/opt/app/run.sh used by root's cron (/etc/cron.d/app): deploy owns /opt/app" {
		t.Errorf("account: %+v", got[1])
	}

	if got, _ := rootWritable.Run(&collect.Facts{IsRoot: true, RootWritable: []collect.WritablePath{}}); len(got) != 0 {
		t.Errorf("nothing writable: got %+v", got)
	}
	if _, skip := rootWritable.Run(&collect.Facts{}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: skip %q", skip)
	}
	partial := &collect.Facts{IsRoot: true, RootWritable: []collect.WritablePath{}, Errors: map[string]string{"root-paths": "only the first 1500 paths were checked"}}
	if got, skip := rootWritable.Run(partial); len(got) != 0 || !strings.Contains(skip, "only partly checked") {
		t.Errorf("partial: got %+v, skip %q", got, skip)
	}
}
