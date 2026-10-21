package checks

import (
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestLoginRecords(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	days := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	run := func(kl *collect.KeyLogins, ls *collect.LogStore, sshd map[string][]string) ([]Finding, string) {
		if sshd == nil {
			sshd = map[string][]string{"loglevel": {"INFO"}}
		}
		return loginRecords.Run(&collect.Facts{IsRoot: true, Errors: map[string]string{}, SSHD: sshd, KeyLogins: kl, LogStore: ls})
	}
	rhel := []string{"journal", "/var/log/secure", "/var/log/secure-20261012", "/var/log/secure-20261005"}
	cases := []struct {
		name  string
		kl    *collect.KeyLogins
		ls    *collect.LogStore
		sev   Severity
		title string
		text  string // in the detail or fix
	}{
		{"RHEL defaults: journal in memory, four weeks of /var/log/secure, installed long ago",
			&collect.KeyLogins{Checked: now, Since: days(30), Sources: rhel}, &collect.LogStore{Journal: "volatile", Born: days(400), Booted: days(12)},
			Low, "Login records go back only 30 days", "rotate count for /var/log/secure (rotate 13"},
		{"Ubuntu: persistent journal that only keeps 40 days",
			&collect.KeyLogins{Checked: now, Since: days(40), Sources: []string{"journal", "/var/log/auth.log", "/var/log/auth.log.1"}}, &collect.LogStore{Journal: "persistent", Born: days(700), Booted: days(3)},
			Low, "Login records go back only 40 days", "SystemMaxUse="},
		{"journal in memory only",
			&collect.KeyLogins{Checked: now, Since: days(3), Sources: []string{"journal"}}, &collect.LogStore{Journal: "volatile", Born: days(300), Booted: days(3)},
			Medium, "Login records do not survive a reboot", "mkdir -p /var/log/journal"},
		{"nothing logs sshd",
			&collect.KeyLogins{Checked: now}, &collect.LogStore{Booted: days(50)},
			Medium, "No login records are kept", "central log server"},
		{"Alpine without an install date, running for months",
			&collect.KeyLogins{Checked: now, Since: days(10), Sources: []string{"/var/log/messages", "/var/log/messages.0"}}, &collect.LogStore{Booted: days(120)},
			Low, "Login records go back only 10 days", "running since"},
	}
	for _, c := range cases {
		got, skip := run(c.kl, c.ls, nil)
		if skip != "" || len(got) != 1 || got[0].CheckID != "LOG-001" || got[0].Severity != c.sev || got[0].Title != c.title || !strings.Contains(got[0].Detail+" "+got[0].Fix, c.text) {
			t.Errorf("%s: %+v (skip %q)", c.name, got, skip)
		}
	}

	// Fine: 90 days or more, or logs that reach back to the installation.
	if got, skip := run(&collect.KeyLogins{Checked: now, Since: days(120), Sources: rhel}, &collect.LogStore{Journal: "volatile", Born: days(400)}, nil); len(got) != 0 || skip != "" {
		t.Errorf("120 days: %+v %q", got, skip)
	}
	if got, skip := run(&collect.KeyLogins{Checked: now, Since: days(14), Sources: []string{"journal"}}, &collect.LogStore{Journal: "persistent", Born: days(15), Booted: days(15)}, nil); len(got) != 0 || skip != "" {
		t.Errorf("new server: %+v %q", got, skip)
	}
	// Unknown install date, rebooted since the logs begin: cannot tell.
	if got, skip := run(&collect.KeyLogins{Checked: now, Since: days(20), Sources: []string{"/var/log/messages"}}, &collect.LogStore{Booted: days(2)}, nil); len(got) != 0 || !strings.Contains(skip, "install date is unknown") {
		t.Errorf("unknown age: %+v %q", got, skip)
	}
	// sshd that logs no logins at all.
	if got, _ := run(nil, nil, map[string][]string{"loglevel": {"ERROR"}}); len(got) != 1 || got[0].Title != "sshd does not log logins" {
		t.Errorf("LogLevel ERROR: %+v", got)
	}
	if _, skip := loginRecords.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
}
