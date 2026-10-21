package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
)

// loginLogDays is how far back sshd's log messages should reach: long
// enough to find out after the fact who logged in, and what ACC-006 needs.
const loginLogDays = keyUnusedDays

var loginRecords = Check{
	ID:    "LOG-001",
	Title: "Login records kept for 90 days",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if lv := collect.SSHDFirst(f.SSHD, "loglevel"); lv == "quiet" || lv == "fatal" || lv == "error" {
			return []Finding{{
				CheckID:  "LOG-001",
				Severity: Medium,
				Title:    "sshd does not log logins",
				Detail:   "LogLevel " + strings.ToUpper(lv) + " leaves out who logged in, from where and with which key",
				Fix:      "Set LogLevel INFO (or VERBOSE) in sshd_config",
			}}, ""
		}
		kl, ls := f.KeyLogins, f.LogStore
		if kl == nil {
			return nil, unavailable(f, "keylogins", "sshd's log messages")
		}
		if ls == nil {
			return nil, unavailable(f, "logstore", "the journal's storage")
		}
		files := false
		for _, s := range kl.Sources {
			files = files || s != "journal"
		}
		const persist = "Make the journal persistent: mkdir -p /var/log/journal && systemctl restart systemd-journald (or Storage=persistent in /etc/systemd/journald.conf), or send the logs to a central log server"
		if !files {
			switch {
			case ls.Journal == "volatile":
				return []Finding{{
					CheckID:  "LOG-001",
					Severity: Medium,
					Title:    "Login records do not survive a reboot",
					Detail:   "the journal is kept in memory (/run/log/journal), and no syslog file has sshd's messages",
					Fix:      persist,
				}}, ""
			case kl.Since.IsZero():
				return []Finding{{
					CheckID:  "LOG-001",
					Severity: Medium,
					Title:    "No login records are kept",
					Detail:   "neither the journal nor /var/log/auth.log, secure or messages has any of sshd's messages",
					Fix:      "Run a journal or syslog daemon that keeps sshd's messages on disk, or send them to a central log server",
				}}, ""
			}
		}
		days := int(kl.Checked.Sub(kl.Since).Hours() / 24)
		if days >= loginLogDays {
			return nil, ""
		}
		// Short logs only say something when the system is older than they
		// are: a new server has only had a few days to log.
		ref, what := ls.Born, "installed"
		if ref.IsZero() {
			ref, what = ls.Booted, "running" // logs cut short while running are cut short
		}
		if ref.IsZero() || !ref.Before(kl.Since.Add(-7*24*time.Hour)) {
			if ls.Born.IsZero() {
				return nil, fmt.Sprintf("sshd's log messages go back %d days, but the system's install date is unknown, so it cannot tell whether they are cut short", days)
			}
			return nil, "" // the logs go back to about when the system was installed
		}
		var ways []string
		switch ls.Journal {
		case "volatile":
			ways = append(ways, "make the journal persistent (mkdir -p /var/log/journal && systemctl restart systemd-journald)")
		case "persistent":
			ways = append(ways, "let the journal keep more (SystemMaxUse= and MaxRetentionSec= in /etc/systemd/journald.conf)")
		}
		if files {
			ways = append(ways, "raise logrotate's rotate count for "+fileSources(kl)+" (rotate 13 with weekly)")
		}
		ways = append(ways, "send the logs to a central log server")
		fix := fmt.Sprintf("Keep at least %d days: %s", loginLogDays, strings.Join(ways, ", or "))
		return []Finding{{
			CheckID:  "LOG-001",
			Severity: Low,
			Title:    fmt.Sprintf("Login records go back only %d days", days),
			Detail: fmt.Sprintf("sshd's oldest message is from %s, but the system has been %s since %s; sources: %s",
				kl.Since.Format("2006-01-02"), what, ref.Format("2006-01-02"), strings.Join(kl.Sources, ", ")),
			Fix: fix,
		}}, ""
	},
}

// fileSources names the log files that hold sshd's messages, without their
// rotated copies (auth.log.2.gz, secure-20261001).
func fileSources(kl *collect.KeyLogins) string {
	var out []string
	for _, s := range kl.Sources {
		for _, base := range []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"} {
			if strings.HasPrefix(s, base) && !contains(out, base) {
				out = append(out, base)
			}
		}
	}
	if len(out) == 0 {
		return "the syslog files"
	}
	return strings.Join(out, ", ")
}
