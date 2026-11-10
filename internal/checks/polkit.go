package checks

import (
	"path"
	"sort"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// rootActions are polkit actions that amount to root, and what they let
// the caller do.
var rootActions = []struct{ id, what string }{
	{"org.freedesktop.policykit.exec", "pkexec (run any program as root)"},
	{"org.freedesktop.systemd1.manage-units", "start any command as root through systemd (systemd-run)"},
	{"org.freedesktop.systemd1.manage-unit-files", "install and enable unit files that run as root"},
	{"org.freedesktop.packagekit.package-install-untrusted", "install unsigned packages"},
	{"org.freedesktop.accounts.user-administration", "set any account's password, root's included"},
	{"org.freedesktop.machine1.host-shell", "open a root shell on the host (machinectl shell)"},
}

var polkitRoot = Check{
	ID:    "ACC-009",
	Title: "Polkit rules that give root without a password",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Polkit == nil {
			return nil, unavailable(f, "polkit", "polkit rules")
		}
		var out []Finding
		report := func(file string, granted []string, users, groups []string, anyone bool) {
			who := "any account"
			sev := Critical
			if !anyone {
				sev = High
				var names []string
				names = append(names, users...)
				for _, g := range groups {
					names = append(names, "group "+g+" ("+summarize(f.GroupMembers(g), 4)+")")
				}
				who = strings.Join(names, ", ")
			}
			out = append(out, Finding{
				CheckID:  "ACC-009",
				Severity: sev,
				Title:    "A polkit rule lets " + who + " become root without a password",
				Detail:   file + " answers yes, without asking for a password, for: " + strings.Join(granted, "; "),
				Fix:      "Remove the rule, or have it ask for an administrator's password (polkit.Result.AUTH_ADMIN, or auth_admin in a .pkla file)",
			})
		}
		if f.Polkit.JSRules {
			for _, r := range f.Polkit.Rules {
				var granted []string
				for _, a := range rootActions {
					covered := !r.ActionCheck || contains(r.Actions, a.id)
					for _, p := range r.Prefixes {
						covered = covered || strings.HasPrefix(a.id, p)
					}
					if covered {
						granted = append(granted, a.what)
					}
				}
				if len(granted) > 0 {
					report(r.File, granted, r.Users, r.Groups, len(r.Users)+len(r.Groups) == 0)
				}
			}
		}
		if f.Polkit.PKLA {
			for _, g := range f.Polkit.Grants {
				var granted []string
				for _, a := range rootActions {
					for _, pat := range g.Actions {
						if ok, _ := path.Match(pat, a.id); ok {
							granted = append(granted, a.what)
							break
						}
					}
				}
				if len(granted) == 0 {
					continue
				}
				var users, groups []string
				anyone := false
				for _, id := range g.Identities {
					kind, name, _ := strings.Cut(id, ":")
					switch {
					case name == "*" || id == "*":
						anyone = true
					case kind == "unix-user":
						users = append(users, name)
					case kind == "unix-group":
						groups = append(groups, name)
					}
				}
				sort.Strings(users)
				report(g.File, granted, users, groups, anyone)
			}
		}
		return out, ""
	},
}
