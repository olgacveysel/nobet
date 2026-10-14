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
