package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// What an auth module returns for an account that is not root and gives
// a wrong password. Modules not listed are taken to have no say (PAM_IGNORE),
// which can only mean fewer findings.
const (
	pamSuccess = "success"
	pamFail    = "auth_err"
	pamIgnore  = "ignore"
)

var pamFails = map[string]bool{
	// They check the password, a token or a key the account does not have.
	"pam_unix.so": true, "pam_unix2.so": true, "pam_sss.so": true, "pam_ldap.so": true, "pam_krb5.so": true,
	"pam_winbind.so": true, "pam_pwdb.so": true, "pam_userdb.so": true, "pam_systemd_home.so": true,
	"pam_radius_auth.so": true, "pam_tacplus.so": true, "pam_google_authenticator.so": true, "pam_oath.so": true,
	"pam_u2f.so": true, "pam_yubico.so": true, "pam_fprintd.so": true,
	"pam_deny.so":   true,
	"pam_rootok.so": true, // the caller is not root
	"pam_wheel.so":  true, // the caller is not in the group (members: see pamSkips)
}

var pamPasses = map[string]bool{
	"pam_permit.so": true, "pam_nologin.so": true, "pam_securetty.so": true, "pam_shells.so": true, "pam_localuser.so": true,
}

func pamOutcome(l collect.PAMLine) string {
	switch {
	case l.Module == "pam_wheel.so" && contains(l.Args, "deny"):
		return pamSuccess // deny inverts it: everyone outside the group passes
	case l.Module == "pam_faillock.so" && contains(l.Args, "authfail"):
		return pamFail
	case l.Module == "pam_faillock.so" && (contains(l.Args, "preauth") || contains(l.Args, "authsucc")):
		return pamSuccess
	case pamPasses[l.Module]:
		return pamSuccess
	case pamFails[l.Module]:
		return pamFail
	}
	return pamIgnore
}

// pamAction is what a line's control does with a module's result: ok,
// done, bad, die, ignore, reset, or a number of lines to jump over. As in
// libpam, a value a bracketed control does not name is bad unless it sets
// default.
func pamAction(control, result string) string {
	var acts map[string]string
	switch control {
	case "required":
		acts = map[string]string{"success": "ok", "ignore": "ignore", "default": "bad"}
	case "requisite":
		acts = map[string]string{"success": "ok", "ignore": "ignore", "default": "die"}
	case "sufficient":
		acts = map[string]string{"success": "done", "default": "ignore"}
	case "optional":
		acts = map[string]string{"success": "ok", "default": "ignore"}
	default:
		acts = map[string]string{}
		for _, kv := range strings.Fields(strings.Trim(control, "[]")) {
			if k, v, ok := strings.Cut(kv, "="); ok {
				acts[k] = v
			}
		}
	}
	if a, ok := acts[result]; ok {
		return a
	}
	if a, ok := acts["default"]; ok {
		return a
	}
	return "bad"
}

// pamEntry is a line of a stack with its includes expanded; a substack is
// one entry holding its own lines.
type pamEntry struct {
	file string
	line collect.PAMLine
	sub  []pamEntry
}

// pamStack expands a service file's auth lines: include and @include put
// the other file's lines in place, substack nests them.
func pamStack(files map[string][]collect.PAMLine, name string, depth int) []pamEntry {
	if depth > 10 {
		return nil
	}
	var out []pamEntry
	for _, l := range files[name] {
		switch {
		case l.Type == "@include" || l.Control == "include":
			out = append(out, pamStack(files, l.Module, depth+1)...)
		case l.Control == "substack":
			out = append(out, pamEntry{file: name, sub: pamStack(files, l.Module, depth+1)})
		default:
			out = append(out, pamEntry{file: name, line: l})
		}
	}
	return out
}

// pamRun evaluates a stack for a wrong password as libpam does, and says
// which line let it through when it passes.
type pamRun struct {
	impression int // 0 undecided, 1 positive, -1 negative
	ok         bool
	by         string // file and module whose success decided
}

func (r *pamRun) eval(stack []pamEntry) (stop bool) {
	for i := 0; i < len(stack); i++ {
		e := stack[i]
		if e.sub != nil {
			r.eval(e.sub) // done and die end only the substack
			continue
		}
		res := pamOutcome(e.line)
		act := pamAction(e.line.Control, res)
		switch act {
		case "ignore":
		case "ok", "done":
			if res != pamIgnore && (r.impression == 0 || (r.impression == 1 && r.ok)) {
				if res == pamSuccess {
					r.by = e.line.Module + " in /etc/pam.d/" + e.file // the last success decides
				}
				r.impression, r.ok = 1, res == pamSuccess
			}
			if act == "done" && r.impression != -1 {
				return true
			}
		case "bad", "die":
			if r.impression != -1 {
				r.impression, r.ok = -1, false
			}
			if act == "die" {
				return true
			}
		case "reset":
			r.impression, r.ok, r.by = 0, false, ""
		default:
			if n, err := strconv.Atoi(act); err == nil && n > 0 {
				i += n
			}
		}
	}
	return false
}

// pamSkips lists the lines of a stack that let some accounts through
// without a password: pam_wheel with trust (members of its group), and a
// sufficient pam_succeed_if (accounts its condition matches).
func pamSkips(f *collect.Facts, stack []pamEntry) []string {
	var out []string
	for _, e := range stack {
		if e.sub != nil {
			out = append(out, pamSkips(f, e.sub)...)
			continue
		}
		l := e.line
		// Only a success that ends the stack skips the password: after a
		// required one, the password module still decides.
		if pamAction(l.Control, pamSuccess) != "done" {
			continue
		}
		switch {
		case l.Module == "pam_wheel.so" && contains(l.Args, "trust") && !contains(l.Args, "deny"):
			group := wheelGroup(f)
			for _, a := range l.Args {
				if g, ok := strings.CutPrefix(a, "group="); ok {
					group = g
				}
			}
			out = append(out, "members of "+group+" ("+summarize(f.GroupMembers(group), 6)+"), by pam_wheel.so trust in /etc/pam.d/"+e.file)
		case l.Module == "pam_succeed_if.so":
			out = append(out, "accounts matching \""+strings.Join(l.Args, " ")+"\", by pam_succeed_if.so in /etc/pam.d/"+e.file)
		}
	}
	return out
}

// wheelGroup is the group pam_wheel uses without group=: wheel, or the
// group with GID 0 where there is no wheel (Debian, Ubuntu).
func wheelGroup(f *collect.Facts) string {
	name := "wheel"
	for _, g := range f.Groups {
		if g.Name == "wheel" {
			return name
		}
		if g.GID == 0 {
			name = g.Name
		}
	}
	return name
}

// pamServices are the services whose stacks give root or a login: su and
// sudo (root for a local account), sshd, login and Cockpit (a login), and
// polkit (pkexec, root).
var pamServices = []string{"su", "su-l", "sudo", "sudo-i", "sshd", "login", "cockpit", "polkit-1"}

var pamBypass = Check{
	ID:    "ACC-008",
	Title: "Authentication that skips the password",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.PAM == nil {
			return nil, "PAM configuration unavailable: " + f.Errors["pam"]
		}
		// sshd only asks PAM for passwords with UsePAM and password or
		// keyboard-interactive authentication.
		// Match blocks count: one view that asks is enough. An unknown
		// config counts as asking.
		sshdPAM := false
		for _, u := range f.SSHDUsers() {
			for _, v := range f.SSHDViews(u) {
				on := func(k string) bool { return len(v.Config[k]) > 0 && v.Config[k][0] == "yes" }
				if v.Config == nil || on("usepam") && (on("passwordauthentication") || on("kbdinteractiveauthentication") || on("challengeresponseauthentication")) {
					sshdPAM = true
				}
			}
		}
		var open, through []string
		var skips []string
		seen := map[string]bool{}
		for _, svc := range pamServices {
			if _, ok := f.PAM[svc]; !ok || (svc == "sshd" && !sshdPAM) {
				continue
			}
			stack := pamStack(f.PAM, svc, 0)
			var r pamRun
			r.eval(stack)
			if r.impression == 1 && r.ok {
				open = append(open, svc)
				if !contains(through, r.by) {
					through = append(through, r.by)
				}
			}
			if svc == "su" || svc == "su-l" {
				for _, s := range pamSkips(f, stack) {
					if !seen[s] {
						seen[s] = true
						skips = append(skips, s)
					}
				}
			}
		}
		var out []Finding
		if len(open) > 0 {
			sort.Strings(through)
			out = append(out, Finding{
				CheckID:  "ACC-008",
				Severity: Critical,
				Title:    "PAM accepts any password for " + strings.Join(open, ", "),
				Detail:   "a wrong password gets through the auth stack (" + strings.Join(through, "; ") + "): any account can become root with su or sudo, or log in, with whatever password it types",
				Fix:      "Restore the distribution's PAM files for these services (or remove the line that lets the password through), and find out who changed them: an auth stack that always succeeds is a classic backdoor",
			})
		}
		if len(skips) > 0 {
			out = append(out, Finding{
				CheckID:  "ACC-008",
				Severity: High,
				Title:    "Some accounts can su to root without a password",
				Detail:   strings.Join(skips, "; "),
				Fix:      "Remove the trust option from pam_wheel.so (and any sufficient pam_succeed_if.so) in /etc/pam.d/su, so su asks for root's password",
			})
		}
		return out, ""
	},
}
