package checks

import (
	"fmt"
	"path"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// suidEscapes are programs that give a shell (or arbitrary file access)
// when they run with SUID root. See https://gtfobins.github.io.
var suidEscapes = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true, "fish": true,
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true, "lua": true, "php": true, "node": true,
	"vi": true, "vim": true, "nano": true, "emacs": true, "less": true, "more": true, "man": true,
	"find": true, "awk": true, "gawk": true, "nawk": true, "env": true, "nmap": true, "tar": true, "zip": true,
	"cp": true, "mv": true, "dd": true, "tee": true, "rsync": true, "git": true, "docker": true, "busybox": true,
}

var suidFiles = Check{
	ID:    "FS-001",
	Title: "Risky SUID files",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.SUID == nil {
			return nil, unavailable(f, "files", "file permissions")
		}
		var escapes, unpackaged, writableDirs []string
		for _, s := range f.SUID {
			base := path.Base(s.Path)
			switch {
			case suidEscapes[base] || strings.HasPrefix(base, "python"):
				escapes = append(escapes, s.Path)
			case inUserWritablePlace(s.Path):
				writableDirs = append(writableDirs, s.Path)
			case s.Owner == "none":
				unpackaged = append(unpackaged, s.Path)
			}
		}
		var out []Finding
		if len(escapes) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-001",
				Severity: Critical,
				Title:    "SUID set on a program that can spawn a root shell",
				Detail:   summarize(escapes, 6),
				Fix:      "Remove the SUID bit (chmod u-s <file>); any local user can become root through these",
			})
		}
		if len(writableDirs) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-001",
				Severity: High,
				Title:    "SUID files in temporary or home directories",
				Detail:   summarize(writableDirs, 6),
				Fix:      "SUID binaries do not belong in /tmp or home directories; investigate how they got there and remove them",
			})
		}
		if len(unpackaged) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-001",
				Severity: Medium,
				Title:    "SUID files not owned by any installed package",
				Detail:   summarize(unpackaged, 6),
				Fix:      "Confirm each one is expected (vendor software in /opt often is); remove the SUID bit otherwise",
			})
		}
		return out, ""
	},
}

var worldWritable = Check{
	ID:    "FS-002",
	Title: "World-writable system paths",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Writable == nil {
			return nil, unavailable(f, "files", "file permissions")
		}
		var files, dirs []string
		for _, w := range f.Writable {
			if w.Dir {
				dirs = append(dirs, w.Path)
			} else {
				files = append(files, w.Path)
			}
		}
		var out []Finding
		if len(files) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-002",
				Severity: High,
				Title:    "World-writable files in system directories",
				Detail:   summarize(files, 6),
				Fix:      "Any user can modify these (chmod o-w <file>); check scripts and configs under /etc first",
			})
		}
		if len(dirs) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-002",
				Severity: High,
				Title:    "World-writable directories without the sticky bit",
				Detail:   summarize(dirs, 6),
				Fix:      "Remove world write access (chmod o-w), or add the sticky bit (chmod +t) if it is a shared drop directory",
			})
		}
		return out, ""
	},
}

var rootWritable = Check{
	ID:    "FS-003",
	Title: "Files root runs that other accounts can change",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.RootWritable == nil {
			collector := "root-jobs"
			if f.Errors["root-paths"] != "" {
				collector = "root-paths"
			}
			return nil, unavailable(f, collector, "what root runs")
		}
		var anyone, accounts []string
		for _, w := range f.RootWritable {
			var who []string
			everyone := false
			for _, wr := range w.Writers {
				everyone = everyone || wr.Everyone
				who = append(who, wr.String())
			}
			entry := w.Path + " " + w.Use() + ": " + strings.Join(who, ", ")
			if everyone {
				anyone = append(anyone, entry)
			} else {
				accounts = append(accounts, entry)
			}
		}
		// A capped listing must not read as a complete one.
		note := ""
		if e := f.Errors["root-paths"]; e != "" {
			if len(anyone)+len(accounts) == 0 {
				return nil, "what root runs was only partly checked: " + e
			}
			note = " (" + e + ")"
		}
		var out []Finding
		if len(anyone) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-003",
				Severity: Critical,
				Title:    "Any account can change files that root runs",
				Detail:   joinSome(anyone, 5) + note,
				Fix:      "Remove world write access (chmod o-w) from these files and the directories above them; any local user or compromised service becomes root through them",
			})
		}
		if len(accounts) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-003",
				Severity: High,
				Title:    "Accounts other than root can change files that root runs",
				Detail:   joinSome(accounts, 5) + note,
				Fix:      "Make these files and every directory above them owned by root and writable only by root (chown root:root, chmod go-w); the accounts named can become root by editing them",
			})
		}
		return out, ""
	},
}

// joinSome joins up to max entries that contain commas themselves.
func joinSome(entries []string, max int) string {
	if len(entries) <= max {
		return strings.Join(entries, "; ")
	}
	return strings.Join(entries[:max], "; ") + fmt.Sprintf("; and %d more", len(entries)-max)
}

func inUserWritablePlace(p string) bool {
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/home/", "/dev/shm/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
