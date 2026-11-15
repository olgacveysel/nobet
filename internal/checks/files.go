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
	"gdb": true, "mawk": true, "nodejs": true,
}

// runsAnything reports whether the program at p is one of suidEscapes, by its
// name without version or variant: the file SUID or capabilities sit on is
// the real one, such as python3.12, perl5.40.1, lua5.4 or Debian's
// vim.basic (/usr/bin/vim is a link to it through /etc/alternatives).
func runsAnything(p string) bool {
	name := path.Base(p)
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return suidEscapes[name] || suidEscapes[strings.TrimRight(name, "0123456789")]
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
			switch {
			case runsAnything(s.Path):
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
				Items:    escapes,
				Fix:      "Remove the SUID bit (chmod u-s <file>); any local user can become root through these",
			})
		}
		if len(writableDirs) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-001",
				Severity: High,
				Title:    "SUID files in temporary or home directories",
				Detail:   summarize(writableDirs, 6),
				Items:    writableDirs,
				Fix:      "SUID binaries do not belong in /tmp or home directories; investigate how they got there and remove them",
			})
		}
		if len(unpackaged) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-001",
				Severity: Medium,
				Title:    "SUID files not owned by any installed package",
				Detail:   summarize(unpackaged, 6),
				Items:    unpackaged,
				Fix:      "Confirm each one is expected (vendor software in /opt often is); remove the SUID bit otherwise",
			})
		}
		return append(out, notListed("FS-001", f.SUIDMore, "SUID files", 500)...), ""
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
				Items:    files,
				Fix:      "Any user can modify these (chmod o-w <file>); check scripts and configs under /etc first",
			})
		}
		if len(dirs) > 0 {
			out = append(out, Finding{
				CheckID:  "FS-002",
				Severity: High,
				Title:    "World-writable directories without the sticky bit",
				Detail:   summarize(dirs, 6),
				Items:    dirs,
				Fix:      "Remove world write access (chmod o-w), or add the sticky bit (chmod +t) if it is a shared drop directory",
			})
		}
		return append(out, notListed("FS-002", f.WritableMore, "world-writable files and directories", 200)...), ""
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
		acl := false
		for _, w := range f.RootWritable {
			var who []string
			everyone := false
			for _, wr := range w.Writers {
				everyone = everyone || wr.Everyone
				acl = acl || strings.HasPrefix(wr.How, "an ACL")
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
				Items:    anyone,
				Fix:      "Remove world write access (chmod o-w) from these files and the directories above them; any local user or compromised service becomes root through them",
			})
		}
		if len(accounts) > 0 {
			fix := "Make these files and every directory above them owned by root and writable only by root (chown root:root, chmod go-w"
			if acl {
				fix += "; setfacl -b removes ACL entries"
			}
			out = append(out, Finding{
				CheckID:  "FS-003",
				Severity: High,
				Title:    "Accounts other than root can change files that root runs",
				Detail:   joinSome(accounts, 5) + note,
				Items:    accounts,
				Fix:      fix + "); the accounts named can become root by editing them",
			})
		}
		if n := len(f.RootUnchecked); n > 0 {
			out = append(out, Finding{
				CheckID:  "FS-003",
				Severity: Info,
				Title:    fmt.Sprintf("%d file(s) root uses were not checked", n),
				Detail:   summarize(f.RootUnchecked, 5) + ": their paths hold characters nobet does not put into a shell script (spaces, quotes, $)",
				Items:    f.RootUnchecked,
				Fix:      "Check who can change them by hand (ls -ld on each and every directory above it), or rename them",
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

// notListed is the Info finding for a search that stopped listing at limit:
// n more were found and not checked, which must not read as a pass.
func notListed(id string, n int, what string, limit int) []Finding {
	if n <= 0 {
		return nil
	}
	return []Finding{{CheckID: id, Severity: Info,
		Title:  fmt.Sprintf("%d more %s were found and not checked", n, what),
		Detail: fmt.Sprintf("the search lists the first %d; this many usually means a copy of a system tree (a chroot, a container's files) in a searched directory", limit),
		Fix:    "Find where they are (find / -xdev ...) and move such trees out of /home, /opt, /srv or /tmp, or check them by hand"}}
}
