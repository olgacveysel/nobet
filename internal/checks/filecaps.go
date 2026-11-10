package checks

import (
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// rootCaps are file capabilities that make root of whoever runs a program
// that can be driven to do anything (an interpreter, a shell, an editor;
// suidEscapes): change uid, write or chmod/chown any file, trace root's
// processes, load kernel modules, raw devices, or put capabilities on
// another file.
var rootCaps = []string{"cap_setuid", "cap_sys_admin", "cap_dac_override", "cap_fowner", "cap_chown",
	"cap_sys_ptrace", "cap_sys_module", "cap_sys_rawio", "cap_setfcap"}

// readCaps let such a program read every file (/etc/shadow, root's keys)
// or join any group (shadow, root's), without root itself.
var readCaps = []string{"cap_dac_read_search", "cap_setgid"}

var fileCaps = Check{
	ID:    "FS-006",
	Title: "Programs with capabilities that give root",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.FileCaps == nil {
			return nil, unavailable(f, "filecaps", "file capabilities")
		}
		held := func(c collect.FileCap, names []string) []string {
			var out []string
			for _, n := range names {
				if c.Permitted(n) {
					out = append(out, n)
				}
			}
			return out
		}
		var shells, readers, writablePlace, unpackaged []string
		for _, c := range f.FileCaps {
			if c.RootID != 0 {
				continue // only for a user namespace whose root is that uid
			}
			root, read := held(c, rootCaps), held(c, readCaps)
			if len(root)+len(read) == 0 {
				continue // cap_net_raw on ping, cap_net_bind_service, ...
			}
			what := c.Path + " (" + strings.Join(append(root, read...), ",") + ")"
			switch {
			case runsAnything(c.Path) && len(root) > 0:
				shells = append(shells, what)
			case runsAnything(c.Path):
				readers = append(readers, what)
			case inUserWritablePlace(c.Path):
				writablePlace = append(writablePlace, what)
			case c.Owner == "none":
				unpackaged = append(unpackaged, what)
			}
		}
		var out []Finding
		if len(shells) > 0 {
			out = append(out, Finding{CheckID: "FS-006", Severity: Critical,
				Title:  "Capabilities on a program that can spawn a root shell",
				Detail: summarize(shells, 6),
				Fix:    "Remove them (setcap -r <file>); any local user can become root through these"})
		}
		if len(readers) > 0 {
			out = append(out, Finding{CheckID: "FS-006", Severity: High,
				Title:  "Capabilities on a program that can read every file",
				Detail: summarize(readers, 6) + ": any local user can read /etc/shadow and root's keys through these",
				Fix:    "Remove them (setcap -r <file>)"})
		}
		if len(writablePlace) > 0 {
			out = append(out, Finding{CheckID: "FS-006", Severity: High,
				Title:  "Programs with root-level capabilities in temporary or home directories",
				Detail: summarize(writablePlace, 6),
				Fix:    "Programs with capabilities do not belong in /tmp or home directories; investigate how they got there and remove them"})
		}
		if len(unpackaged) > 0 {
			out = append(out, Finding{CheckID: "FS-006", Severity: Medium,
				Title:  "Programs with root-level capabilities not owned by any installed package",
				Detail: summarize(unpackaged, 6),
				Fix:    "Confirm each one is expected and cannot be made to run other code; remove the capabilities otherwise (setcap -r <file>)"})
		}
		return out, ""
	},
}
