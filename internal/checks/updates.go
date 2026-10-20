package checks

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/olgacveysel/nobet/internal/collect"
)

var updateFix = map[string]string{
	"apt":    "apt-get update && apt-get upgrade (or enable unattended-upgrades)",
	"dnf":    "dnf upgrade --security (or enable dnf-automatic)",
	"dnf5":   "dnf upgrade --security (or enable dnf5-plugin-automatic)",
	"yum":    "yum update --security",
	"zypper": "zypper patch --category security",
	"apk":    "apk upgrade",
}

// refreshHint is how to refresh each manager's package indexes. nobet never
// does this itself.
var refreshHint = map[string]string{
	"apt":    "apt-get update",
	"dnf":    "dnf makecache",
	"dnf5":   "dnf makecache",
	"yum":    "yum makecache",
	"zypper": "zypper refresh",
	"apk":    "apk update",
}

var pendingSecurityUpdates = Check{
	ID:    "UPD-001",
	Title: "Pending security updates",
	Run: func(f *collect.Facts) ([]Finding, string) {
		u := f.Updates
		switch {
		case u == nil:
			return nil, "could not query the package manager: " + f.Errors["updates"]
		case u.Manager == "":
			return nil, "no supported package manager found (apt, dnf, dnf5, yum, zypper, apk)"
		case u.Err != "" && strings.Contains(u.Err, "cache"):
			return nil, u.Err + " (run '" + refreshHint[u.Manager] + "')"
		case u.Err != "" && u.Manager != "apt":
			return nil, u.Err + "; the package index cache may be missing (run '" + refreshHint[u.Manager] + "')"
		case u.Err != "":
			return nil, u.Err
		case u.Manager == "apk":
			if len(u.Pending) == 0 {
				return nil, ""
			}
			return []Finding{{
				CheckID:  "UPD-001",
				Severity: Medium,
				Title:    fmt.Sprintf("%d pending package update(s)", len(u.Pending)),
				Detail:   "apk: " + summarize(u.Pending, 8) + "; apk does not say which updates fix security issues, and Alpine's stable branches receive mostly security and bug fixes",
				Fix:      updateFix[u.Manager],
			}}, ""
		case len(u.Security) == 0:
			return nil, ""
		}

		sev := Medium
		names := make([]string, 0, len(u.Security))
		for _, s := range u.Security {
			if s.Severity == "critical" || s.Severity == "important" {
				sev = High
			}
			names = append(names, s.Package)
		}
		return []Finding{{
			CheckID:  "UPD-001",
			Severity: sev,
			Title:    fmt.Sprintf("%d pending security update(s)", len(u.Security)),
			Detail:   u.Manager + ": " + summarize(names, 8),
			Fix:      updateFix[u.Manager],
		}}, ""
	},
}

var rebootRequired = Check{
	ID:    "UPD-002",
	Title: "Reboot required",
	Run: func(f *collect.Facts) ([]Finding, string) {
		r := f.Reboot
		if r == nil {
			return nil, "could not determine kernel versions: " + f.Errors["reboot"]
		}
		var reasons []string
		if r.Latest != "" && r.Running != "" && r.Latest != r.Running && startsWithDigit(r.Latest) {
			reasons = append(reasons, fmt.Sprintf("running kernel %s, newest installed %s", r.Running, r.Latest))
		}
		for _, fl := range r.Flags {
			reasons = append(reasons, fl+" exists")
		}
		if len(reasons) == 0 {
			return nil, ""
		}
		detail := strings.Join(reasons, "; ")
		if len(r.Packages) > 0 {
			detail += "; requested by " + summarize(r.Packages, 5)
		}
		return []Finding{{
			CheckID:  "UPD-002",
			Severity: Medium,
			Title:    "Reboot required: installed updates are not active yet",
			Detail:   detail,
			Fix:      "Schedule a reboot so the patched kernel and libraries are actually in use",
		}}, ""
	},
}

var staleUpdateLists = Check{
	ID:    "UPD-003",
	Title: "Stale package indexes",
	Run: func(f *collect.Facts) ([]Finding, string) {
		u := f.Updates
		if u == nil || u.ListsAgeDays < 0 {
			return nil, "" // no index files to date; UPD-001 reports a missing cache
		}
		if u.ListsAgeDays <= 7 {
			return nil, ""
		}
		return []Finding{{
			CheckID:  "UPD-003",
			Severity: Low,
			Title:    fmt.Sprintf("Package indexes were last refreshed %d days ago", u.ListsAgeDays),
			Detail:   u.Manager + ": pending update counts are based on these indexes and may be incomplete",
			Fix:      "Refresh them regularly ('" + refreshHint[u.Manager] + "'), for example from a daily timer or cron job",
		}}, ""
	},
}

var autoUpdates = Check{
	ID:    "UPD-005",
	Title: "Automatic security updates",
	Run: func(f *collect.Facts) ([]Finding, string) {
		a := f.AutoUpdates
		if a == nil {
			return nil, "could not check how updates are installed: " + f.Errors["autoupdates"]
		}
		manager := ""
		if f.Updates != nil {
			manager = f.Updates.Manager
		}
		var why, fix string
		switch manager {
		case "apt":
			switch {
			case a["unattended-upgrades"] != "installed":
				why = "unattended-upgrades is not installed"
			case !nonZero(a["periodic.Unattended-Upgrade"]):
				why = "APT::Periodic::Unattended-Upgrade is " + orUnset(a["periodic.Unattended-Upgrade"])
			case !nonZero(a["periodic.Update-Package-Lists"]):
				why = "APT::Periodic::Update-Package-Lists is " + orUnset(a["periodic.Update-Package-Lists"]) + ", so upgrades would use stale package lists"
			case disabled(a["unit.apt-daily-upgrade.timer"]):
				why = "apt-daily-upgrade.timer, which runs them, is " + a["unit.apt-daily-upgrade.timer"]
			}
			fix = "apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades (it installs security updates by default)"
		case "dnf", "dnf5", "yum":
			if autoInstalls(a) {
				return nil, ""
			}
			why = "no dnf-automatic, dnf5-automatic or yum-cron timer installs updates"
			for _, u := range []string{"dnf-automatic.timer", "dnf5-automatic.timer", "yum-cron.service"} {
				if a["unit."+u] == "enabled" {
					why = u + " is enabled but only downloads or reports (apply_updates is not yes)"
				}
			}
			switch manager {
			case "dnf5":
				fix = "dnf install dnf5-plugin-automatic, set apply_updates = yes (and upgrade_type = security) in /etc/dnf/automatic.conf, then systemctl enable --now dnf5-automatic.timer"
			case "yum":
				fix = "yum install yum-cron, set apply_updates = yes and update_cmd = security in /etc/yum/yum-cron.conf, then systemctl enable --now yum-cron"
			default:
				fix = "dnf install dnf-automatic, set upgrade_type = security in /etc/dnf/automatic.conf, then systemctl enable --now dnf-automatic-install.timer"
			}
		case "":
			return nil, "no supported package manager found"
		default:
			return nil, manager + " has no standard automatic update service to check"
		}
		if why == "" {
			return nil, ""
		}
		return []Finding{{
			CheckID:  "UPD-005",
			Severity: Low,
			Title:    "Security updates are not installed automatically",
			Detail:   why + "; if updates are rolled out another way (configuration management, patch windows), allowlist this",
			Fix:      fix,
		}}, ""
	},
}

// autoInstalls reports whether a dnf, dnf5 or yum timer installs updates.
func autoInstalls(a map[string]string) bool {
	if a["unit.dnf-automatic-install.timer"] == "enabled" {
		return true
	}
	applies := false
	for k, v := range a {
		if strings.HasPrefix(k, "apply.") && (strings.EqualFold(v, "yes") || strings.EqualFold(v, "true") || v == "1") {
			applies = true
		}
	}
	for _, u := range []string{"dnf-automatic.timer", "dnf5-automatic.timer", "yum-cron.service"} {
		if a["unit."+u] == "enabled" && applies {
			return true
		}
	}
	return false
}

// nonZero reports whether an APT::Periodic interval is set ("1", "7", "always").
func nonZero(v string) bool {
	return v != "" && v != "0"
}

func disabled(state string) bool {
	return state == "disabled" || state == "masked"
}

func orUnset(v string) string {
	if v == "" {
		return "not set"
	}
	return v
}

// summarize joins up to max names and notes how many were left out.
func summarize(names []string, max int) string {
	if len(names) <= max {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:max], ", ") + fmt.Sprintf(" and %d more", len(names)-max)
}

func startsWithDigit(s string) bool {
	return s != "" && unicode.IsDigit(rune(s[0]))
}
