package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestUnusedKeys(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	days := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	f := &collect.Facts{
		IsRoot: true,
		SSHD: map[string][]string{"pubkeyauthentication": {"yes"}, "permitrootlogin": {"prohibit-password"},
			"loglevel": {"INFO"}, "fingerprinthash": {"SHA256"}},
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0, Home: "/root"}, {Name: "operator", UID: 11, Home: "/root", Shell: "/sbin/nologin"},
			{Name: "deploy", UID: 1000}, {Name: "backup", UID: 1001}, {Name: "gone", UID: 1002}},
		Shadow: []collect.ShadowEntry{{User: "gone", Password: collect.PasswordSet, Expired: true}},
		SudoRights: map[string][]collect.SudoEntry{
			"deploy": {{RunAs: "ALL : ALL", NoPasswd: true, Commands: []string{"ALL"}}},
		},
		AuthKeys: []collect.AuthKey{
			// operator's home is /root (RHEL), so sshd reads root's file for it
			// too: a line counts as used when either logged in with it.
			{User: "root", File: "/root/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:used", Comment: "nobet-scan"},
			{User: "operator", File: "/root/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:used", Comment: "nobet-scan"},
			{User: "root", File: "/root/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:stale", Comment: "alice@laptop"},
			{User: "operator", File: "/root/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:stale", Comment: "alice@laptop"},
			{User: "root", File: "/root/.ssh/authorized_keys2", Type: "ssh-ed25519", Fingerprint: "SHA256:stale", Comment: "alice@laptop"},
			{User: "deploy", File: "/home/deploy/.ssh/authorized_keys", Type: "ssh-rsa", Fingerprint: "SHA256:never"},
			{User: "backup", File: "/home/backup/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:never2"},
			{User: "gone", File: "/home/gone/.ssh/authorized_keys", Type: "ssh-ed25519", Fingerprint: "SHA256:expired"},
		},
		KeyLogins: &collect.KeyLogins{Checked: now, Since: days(200), Last: map[string]time.Time{
			"root SHA256:used":  days(10),
			"root SHA256:stale": days(120),
		}},
		Errors: map[string]string{},
	}

	got, skip := unusedKeys.Run(f)
	if skip != "" || len(got) != 4 {
		t.Fatalf("got %d findings (skip %q): %+v", len(got), skip, got)
	}
	want := []struct {
		sev     Severity
		title   string
		details []string
	}{
		{Medium, "SSH key for root, operator has not logged in for 90 days",
			[]string{"SHA256:stale ed25519 alice@laptop in /root/.ssh/authorized_keys;", "last login 2026-06-23, 120 days ago"}},
		{Medium, "SSH key for root has not logged in", []string{"in /root/.ssh/authorized_keys2;"}},
		{Medium, "SSH key for deploy has not logged in", []string{"SHA256:never rsa in", "no login since 2026-04-04, as far back as the logs go"}}, // sudo ALL
		{Low, "SSH key for backup has not logged in", []string{"SHA256:never2"}},
	}
	for i, w := range want {
		g := got[i]
		if g.CheckID != "ACC-006" || g.Severity != w.sev || !strings.HasPrefix(g.Title, w.title) {
			t.Errorf("finding %d: %+v", i, g)
		}
		for _, d := range w.details {
			if !strings.Contains(g.Detail, d) {
				t.Errorf("finding %d detail %q lacks %q", i, g.Detail, d)
			}
		}
	}

	// Logs that only go back 30 days cannot tell about the four key lines
	// without a recent login, but a recently used key is known to be fine.
	f.KeyLogins = &collect.KeyLogins{Checked: now, Since: days(30), Last: map[string]time.Time{"root SHA256:used": days(10)}}
	if got, skip := unusedKeys.Run(f); len(got) != 0 || !strings.Contains(skip, "4 key(s)") || !strings.Contains(skip, "90 days are needed") || !strings.Contains(skip, "/var/log/journal") {
		t.Errorf("short logs: %+v, %q", got, skip)
	}
	f.AuthKeys = f.AuthKeys[:2]
	if got, skip := unusedKeys.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("every key logged in recently: %+v, %q", got, skip)
	}
	f.AuthKeys = []collect.AuthKey{{User: "backup", File: "/home/backup/.ssh/authorized_keys", Fingerprint: "SHA256:never2"}}
	f.KeyLogins = &collect.KeyLogins{Checked: now}
	if _, skip := unusedKeys.Run(f); !strings.Contains(skip, "none were found") {
		t.Errorf("no logs at all: %q", skip)
	}

	// sshd settings that keep the logs from telling.
	f.KeyLogins = &collect.KeyLogins{Checked: now, Since: days(200)}
	f.SSHD["loglevel"] = []string{"ERROR"}
	if _, skip := unusedKeys.Run(f); !strings.Contains(skip, "LogLevel ERROR") {
		t.Errorf("LogLevel ERROR: %q", skip)
	}
	f.SSHD["loglevel"] = []string{"VERBOSE"}
	f.SSHD["fingerprinthash"] = []string{"MD5"}
	if _, skip := unusedKeys.Run(f); !strings.Contains(skip, "MD5") {
		t.Errorf("FingerprintHash MD5: %q", skip)
	}

	if _, skip := unusedKeys.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
}

func TestWeakPasswordHashes(t *testing.T) {
	f := &collect.Facts{
		IsRoot: true,
		Errors: map[string]string{},
		Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "legacy", UID: 1000}, {Name: "app", UID: 1001}},
		Shadow: []collect.ShadowEntry{
			{User: "root", Password: collect.PasswordSet, Hash: "md5"},
			{User: "legacy", Password: collect.PasswordSet, Hash: "des"},
			{User: "app", Password: collect.PasswordSet, Hash: "yescrypt"},
			{User: "gone", Password: collect.PasswordSet, Hash: "des", Expired: true}, // cannot log in
			{User: "nologin", Password: collect.PasswordLocked},
		},
	}
	got, skip := weakPasswordHashes.Run(f)
	if skip != "" || len(got) != 2 {
		t.Fatalf("got %+v (skip %q)", got, skip)
	}
	if got[0].Severity != Medium || got[0].Detail[:10] != "root (MD5)" || got[1].Severity != Low || !strings.HasPrefix(got[1].Detail, "legacy (DES);") {
		t.Errorf("findings: %+v", got)
	}
	f.Shadow = []collect.ShadowEntry{{User: "app", Password: collect.PasswordSet, Hash: "sha512"}}
	if got, skip := weakPasswordHashes.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("strong hashes: %+v %q", got, skip)
	}
	if _, skip := weakPasswordHashes.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
}
