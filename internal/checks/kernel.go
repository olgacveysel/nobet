package checks

import (
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// kernelSettings are sysctls whose kernel and distribution defaults are
// safe everywhere nobet runs, so a different value was set on purpose or
// by mistake. Settings whose defaults differ between distributions (such
// as kernel.yama.ptrace_scope, 0 on RHEL) are left out to avoid noise.
var kernelSettings = []struct {
	key, want string
	bad       func(v string) bool
	sev       Severity
	why       string
}{
	{"kernel.randomize_va_space", "2", func(v string) bool { return v != "2" }, Medium, "address space layout randomization is weakened or off"},
	{"fs.protected_symlinks", "1", is("0"), Medium, "root can be tricked into following other users' symlinks in /tmp and other sticky directories"},
	{"fs.protected_hardlinks", "1", is("0"), Medium, "users can hard-link files they do not own, an old way into setuid programs"},
	{"fs.suid_dumpable", "0 or 2", is("1"), Medium, "setuid programs leave core dumps that the user who ran them can read"},
	{"net.ipv4.tcp_syncookies", "1", is("0"), Low, "no SYN flood protection"},
	{"net.ipv4.conf.all.accept_source_route", "0", is("1"), Low, "source-routed packets are accepted"},
}

func is(want string) func(string) bool { return func(v string) bool { return v == want } }

var kernelHardening = Check{
	ID:    "KRN-001",
	Title: "Kernel hardening settings",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Sysctl == nil {
			return nil, "could not read kernel settings: " + f.Errors["sysctl"]
		}
		sev := Severity(-1)
		var bad, unread []string
		for _, s := range kernelSettings {
			v, ok := f.Sysctl[s.key]
			switch {
			case !ok:
				unread = append(unread, s.key)
			case s.bad(v):
				bad = append(bad, s.key+" = "+v+" (want "+s.want+"): "+s.why)
				if s.sev > sev {
					sev = s.sev
				}
			}
		}
		if len(bad) == 0 {
			if len(unread) > 0 {
				// Some are root-only (fs.protected_*): no verdict on those.
				reason := "could not read " + strings.Join(unread, ", ")
				if !f.Privileged() {
					reason += " (needs root or passwordless sudo)"
				}
				return nil, reason
			}
			return nil, ""
		}
		return []Finding{{
			CheckID:  "KRN-001",
			Severity: sev,
			Title:    "Kernel hardening settings are weakened",
			Detail:   strings.Join(bad, "; "),
			Fix:      "Set them back in /etc/sysctl.d/99-hardening.conf (for example kernel.randomize_va_space = 2) and apply with sysctl --system; check what set them first",
		}}, ""
	},
}
