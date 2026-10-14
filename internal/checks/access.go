package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

var uidZeroAccounts = Check{
	ID:    "ACC-001",
	Title: "Accounts with UID 0 besides root",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Passwd == nil {
			return nil, "could not read /etc/passwd: " + f.Errors["passwd"]
		}
		var out []Finding
		for _, p := range f.Passwd {
			if p.UID == 0 && p.Name != "root" {
				out = append(out, Finding{
					CheckID:  "ACC-001",
					Severity: Critical,
					Title:    "Account " + p.Name + " has UID 0 (full root privileges)",
					Detail:   "shell: " + p.Shell,
					Fix:      "Remove the account or give it a non-zero UID; grant privilege through sudo instead",
				})
			}
		}
		return out, ""
	},
}

var sudoNoPassword = Check{
	ID:    "ACC-002",
	Title: "Passwordless sudo",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Sudoers == nil {
			return nil, unavailable(f, "sudoers", "sudoers")
		}
		var out []Finding
		for _, l := range f.Sudoers {
			switch {
			case strings.HasPrefix(l.Text, "Defaults") && strings.Contains(l.Text, "!authenticate"):
				out = append(out, Finding{
					CheckID:  "ACC-002",
					Severity: High,
					Title:    "sudo password prompts are disabled by a Defaults rule",
					Detail:   l.File + ": " + l.Text,
					Fix:      "Remove '!authenticate' so sudo asks for a password",
				})
			case strings.Contains(l.Text, "NOPASSWD"):
				fnd := Finding{
					CheckID:  "ACC-002",
					Severity: Medium,
					Title:    "Passwordless sudo rule",
					Detail:   l.File + ": " + l.Text,
					Fix:      "Limit NOPASSWD to the specific commands that need it",
				}
				if grantsAll(l.Text) {
					fnd.Severity = High
					fnd.Title = "Passwordless sudo for ALL commands"
				}
				out = append(out, fnd)
			}
		}
		return out, ""
	},
}

// grantsAll reports whether a NOPASSWD rule's command list includes ALL.
func grantsAll(rule string) bool {
	_, cmds, ok := strings.Cut(rule, "NOPASSWD:")
	if !ok {
		return false
	}
	for _, c := range strings.Split(cmds, ",") {
		if strings.TrimSpace(c) == "ALL" {
			return true
		}
	}
	return false
}

var rootGroupMembers = Check{
	ID:    "ACC-003",
	Title: "Members of root-equivalent groups",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Groups == nil || f.Passwd == nil {
			return nil, "could not read /etc/group or /etc/passwd: " + f.Errors["group"] + f.Errors["passwd"]
		}
		var out []Finding
		for _, g := range collect.RootEquivalentGroups {
			members := f.GroupMembers(g)
			if len(members) == 0 {
				continue
			}
			out = append(out, Finding{
				CheckID:  "ACC-003",
				Severity: High,
				Title:    fmt.Sprintf("%d account(s) in the %s group, which is equivalent to root", len(members), g),
				Detail:   "members: " + strings.Join(members, ", "),
				Fix:      "Membership in " + g + " grants root on the host; limit it to trusted admins or use a rootless setup",
			})
		}
		return out, ""
	},
}

var sudoShellEscape = Check{
	ID:    "ACC-004",
	Title: "Limited sudo rules that escape to root",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.SudoRights == nil {
			return nil, unavailable(f, "sudo-rights", "sudo rights")
		}
		users := make([]string, 0, len(f.SudoRights))
		for u := range f.SudoRights {
			users = append(users, u)
		}
		sort.Strings(users)

		var out []Finding
		for _, u := range users {
			if u == "root" || hasRootAll(f, u) {
				continue // already has full root, nothing to escape from
			}
			var esc []string
			nopasswd := false
			for _, e := range f.SudoRights[u] {
				for _, c := range e.Escapes() {
					if usableSudo(f, u, e, c) {
						esc = append(esc, c)
						nopasswd = nopasswd || e.NoPasswd || f.SudoAuthFor(u, "root", c) == collect.SudoAuthNone
					}
				}
			}
			if len(esc) == 0 {
				continue
			}
			detail := summarize(esc, 4)
			if nopasswd {
				detail += " (no password needed)"
			}
			out = append(out, Finding{
				CheckID:  "ACC-004",
				Severity: High,
				Title:    "sudo rule for " + u + " gives a root shell despite limiting commands",
				Detail:   detail,
				Fix:      "These programs can spawn a shell or overwrite any file as root (see gtfobins.github.io); allow a wrapper script with fixed arguments, use sudoedit for editing, or add NOEXEC where it suffices",
			})
		}
		return out, ""
	},
}

// usableSudo reports whether user can run cmd under rule e with their own
// credentials: not when sudo asks for root's password (rootpw, targetpw),
// for a locked password, or on an expired account.
func usableSudo(f *collect.Facts, user string, e collect.SudoEntry, cmd string) bool {
	pw, expired, _ := f.Password(user)
	if expired {
		return false // sudo's PAM account check refuses expired accounts
	}
	if e.NoPasswd {
		return true
	}
	switch f.SudoAuthFor(user, "root", cmd) {
	case collect.SudoAuthNone:
		return true
	case collect.SudoAuthTarget:
		return false
	}
	return pw != collect.PasswordLocked
}

// hasRootAll reports whether user may run any command as root with their
// own credentials.
func hasRootAll(f *collect.Facts, user string) bool {
	for _, e := range f.SudoRights[user] {
		if e.RootAll() && usableSudo(f, user, e, "ALL") {
			return true
		}
	}
	return false
}

var emptyPasswords = Check{
	ID:    "ACC-005",
	Title: "Accounts with an empty password",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Shadow == nil {
			return nil, unavailable(f, "shadow", "password states")
		}
		shells := map[string]string{}
		for _, p := range f.Passwd {
			shells[p.Name] = p.Shell
		}
		var rootCapable, others []string
		for _, s := range f.Shadow {
			if s.Password != collect.PasswordEmpty || s.Expired || !loginShell(shells[s.User]) {
				continue
			}
			if canBecomeRoot(f, s.User) {
				rootCapable = append(rootCapable, s.User)
			} else {
				others = append(others, s.User)
			}
		}
		const fix = "Set a password or lock the account (passwd -l <user>); with pam_unix nullok, the default on most distributions, su and the console accept an empty password"
		var out []Finding
		if len(rootCapable) > 0 {
			out = append(out, Finding{
				CheckID:  "ACC-005",
				Severity: Critical,
				Title:    "Root-capable accounts have no password",
				Detail:   summarize(rootCapable, 6) + "; any local user can su to them and then become root",
				Fix:      fix,
			})
		}
		if len(others) > 0 {
			out = append(out, Finding{
				CheckID:  "ACC-005",
				Severity: High,
				Title:    "Accounts have no password",
				Detail:   summarize(others, 6) + "; any local user can su to them",
				Fix:      fix,
			})
		}
		return out, ""
	},
}

// loginShell reports whether a shell lets the account log in or su.
func loginShell(shell string) bool {
	return shell != "" && !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false")
}

// canBecomeRoot reports whether user is UID 0, may run any command (or a
// shell escape) as root through sudo, or is in a root-equivalent group.
func canBecomeRoot(f *collect.Facts, user string) bool {
	for _, p := range f.Passwd {
		if p.Name == user && p.UID == 0 {
			return true
		}
	}
	for _, e := range f.SudoRights[user] {
		if e.RootAll() && usableSudo(f, user, e, "ALL") {
			return true
		}
		for _, c := range e.Escapes() {
			if usableSudo(f, user, e, c) {
				return true
			}
		}
	}
	for _, g := range collect.RootEquivalentGroups {
		for _, m := range f.GroupMembers(g) {
			if m == user {
				return true
			}
		}
	}
	return false
}
