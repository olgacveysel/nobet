package collect

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// RootJob is something root runs or trusts, and the files that decide what
// it does: a cron job and the programs on its command line, a systemd
// service, the scripts run-parts runs, root's shell startup files, a sudo
// rule's commands, or the account and sudo configuration. Whoever can change
// one of those files can become root.
type RootJob struct {
	Kind    string   `json:"kind"`              // cron, run-parts, systemd, startup, sudo, config
	Source  string   `json:"source"`            // where it is defined, e.g. /etc/cron.d/backup or nginx.service
	Paths   []string `json:"paths"`             // files root runs or reads; for a directory, every file in it
	Account string   `json:"account,omitempty"` // login: the account whose logins use the files
}

// PathEntry is the owner and mode of one file or directory.
type PathEntry struct {
	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Mode uint32 `json:"mode"`          // permission bits, including setuid, setgid and sticky
	Type string `json:"type"`          // file, dir, link or other
	ACL  *ACL   `json:"acl,omitempty"` // extended ACL entries, when it has any and getfacl could read them
}

// Writer is an account other than root that can change a file root runs.
type Writer struct {
	Account  string `json:"account,omitempty"` // account name, or "uid N" for an owner without one
	Everyone bool   `json:"everyone,omitempty"`
	Path     string `json:"path"`              // the file or directory that lets it: the file itself or one above it
	How      string `json:"how"`               // "owner", "group <name>" or "world-writable"
	Through  string `json:"through,omitempty"` // the script's #! interpreter, when that is what can be changed
}

func (w Writer) String() string {
	what, note := w.Path, ""
	switch {
	case w.Through == w.Path:
		what = "its interpreter " + w.Path
	case w.Through != "":
		note = " (above its interpreter " + w.Through + ")"
	}
	switch {
	case w.Everyone:
		return what + " is world-writable" + note
	case w.How == "owner":
		return w.Account + " owns " + what + note
	default:
		return w.Account + " through " + w.How + " on " + what + note
	}
}

// WritablePath is a file root runs or trusts that someone else can change.
type WritablePath struct {
	Kind     string   `json:"kind"`   // as in RootJob
	Source   string   `json:"source"` // as in RootJob
	Path     string   `json:"path"`
	CalledBy string   `json:"called_by,omitempty"` // the script that runs or sources Path, when the job names that script
	Writers  []Writer `json:"writers"`
}

// Use says what root does with the file, e.g. "used by root's cron
// (/etc/cron.d/backup)".
func (w WritablePath) Use() string {
	if w.CalledBy != "" {
		v := w
		v.CalledBy = ""
		return "run or sourced by " + w.CalledBy + ", which is " + v.Use()
	}
	switch w.Kind {
	case "cron":
		return "used by root's cron (" + w.Source + ")"
	case "run-parts":
		return "run by root's cron (" + w.Source + ")"
	case "systemd":
		return "used by " + w.Source + ", which runs as root"
	case "systemd-privileged":
		return "run as root by a + or ! command of " + w.Source
	case "path":
		return "on root's PATH (" + w.Source + ")"
	case "startup":
		return "run by root's login shells"
	case "sudo":
		return "named in the " + w.Source
	case "config":
		return "trusted by logins or the loader"
	case "sudoers":
		return "read by sudo"
	case "conf":
		return "configures " + w.Source
	case "login":
		return "used by the logins of " + w.Source + ", which can become root"
	}
	return w.Kind + " " + w.Source
}

// maxRootPaths caps the paths checked in one host, so the generated script
// stays far below the kernel's 128 KiB limit for one argument.
const maxRootPaths = 1500

// Lists what root runs or trusts, between section markers that
// parseRootJobs reads: cron files (system ones have a user field), anacron,
// run-parts directories with their scripts, root's shell startup files,
// account and sudo configuration, and systemd services. Needs root for
// root's crontab.
const rootJobsScript = `PATH=$PATH:/usr/sbin:/sbin
for f in /etc/crontab /etc/cron.d/*; do
  [ -f "$f" ] && { echo "@@cron system $f"; cat "$f"; }
done
for f in /var/spool/cron/crontabs/root /var/spool/cron/root /etc/crontabs/root; do
  [ -f "$f" ] && { echo "@@cron user $f"; cat "$f"; }
done
[ -f /etc/anacrontab ] && { echo "@@cron anacron /etc/anacrontab"; cat /etc/anacrontab; }
if [ -d /etc/cron.d ]; then echo "@@files cron /etc/cron.d"; echo /etc/cron.d; fi
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/15min /etc/periodic/hourly /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
  [ -d "$d" ] || continue
  echo "@@files run-parts $d"
  echo "$d"
  for f in "$d"/*; do [ -f "$f" ] && echo "$f"; done
done
echo "@@files startup root's shell startup files"
for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zprofile /etc/zsh/zshrc /etc/zsh/zprofile /root/.profile /root/.bashrc /root/.bash_profile /root/.bash_login /root/.zshrc /root/.zprofile /etc/profile.d /etc/profile.d/*.sh; do
  [ -e "$f" ] && echo "$f"
done
# Commands root types or scripts call without a path come from these.
echo "@@files path standard directories"
for d in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do [ -d "$d" ] && echo "$d"; done
if [ -f /etc/environment ]; then
  echo "@@files path /etc/environment"
  sed -n 's/^[[:space:]]*PATH=//p' /etc/environment | tr -d '"' | tr ':' '\n'
fi
echo "@@files config account and loader configuration"
for f in /etc/passwd /etc/shadow /etc/group /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/ld.so.conf.d/*; do
  [ -e "$f" ] && echo "$f"
done
# sudo refuses a sudoers file that root does not own, or that a group
# other than root's can write, and a file created in sudoers.d is its
# creator's: only the files themselves count (see writablePaths).
echo "@@files sudoers sudo"
for f in /etc/sudoers /etc/sudoers.d/*; do [ -f "$f" ] && echo "$f"; done
# Configuration that makes root run commands, none of which checks who
# owns it (logrotate and NetworkManager's dispatcher do, so they are left
# out).
conf() { # SOURCE PATHS...
  s=$1; shift
  echo "@@files conf $s"
  for f; do [ -e "$f" ] && echo "$f"; done
}
conf "PAM, which decides su, sudo and logins" /etc/pam.d /etc/pam.d/*
conf "sshd, when it restarts (AuthorizedKeysCommand and the like)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/ssh/sshd_config.d/*
conf "polkit, which pkexec asks" /etc/polkit-1/rules.d /etc/polkit-1/rules.d/* /etc/polkit-1/localauthority /etc/polkit-1/localauthority/*.d /etc/polkit-1/localauthority/*.d/*
conf "APT, whose hooks run as root (apt and its daily timers)" /etc/apt/apt.conf /etc/apt/apt.conf.d /etc/apt/apt.conf.d/*
conf "modprobe, whose install lines run as root when a module loads" /etc/modprobe.conf /etc/modprobe.d /etc/modprobe.d/*
conf "update-motd, run as root at every login" /etc/update-motd.d /etc/update-motd.d/*
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  echo "@@files systemd systemd unit directory"
  echo /etc/systemd/system
  echo "@@systemd"
  # The Ex properties (systemd 243+) carry the + and ! flags: those
  # commands run as root even in a service that runs as another user.
  systemctl show --all --no-pager -p Id -p LoadState -p User -p DynamicUser -p FragmentPath -p DropInPaths \
    -p ExecStart -p ExecStartPre -p ExecStartPost -p ExecReload -p ExecStop -p ExecStopPost \
    -p ExecStartEx -p ExecStartPreEx -p ExecStartPostEx -p ExecReloadEx -p ExecStopEx -p ExecStopPostEx '*.service' || echo "@@failed"
fi
echo "@@end"
`

// parseRootJobs reads rootJobsScript output. It returns nil when the output
// is incomplete (no closing marker, or systemctl failed).
func parseRootJobs(s string) []RootJob {
	jobs := []RootJob{}
	var head string
	var body []string
	complete := false
	flush := func() {
		switch kind, rest, _ := strings.Cut(head, " "); kind {
		case "@@cron":
			flavor, file, _ := strings.Cut(rest, " ")
			if j := cronJob(file, flavor, body); len(j.Paths) > 0 {
				jobs = append(jobs, j)
			}
		case "@@files":
			k, source, _ := strings.Cut(rest, " ")
			j := RootJob{Kind: k, Source: source}
			for _, l := range body {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "/") {
					j.Paths = append(j.Paths, l)
				}
			}
			if len(j.Paths) > 0 {
				jobs = append(jobs, j)
			}
		case "@@systemd":
			jobs = append(jobs, systemdJobs(body)...)
		}
		head, body = "", nil
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "@@failed":
			return nil
		case line == "@@end":
			flush()
			complete = true
		case strings.HasPrefix(line, "@@"):
			flush()
			head = line
		default:
			body = append(body, line)
		}
	}
	if !complete {
		return nil
	}
	return jobs
}

// cronJob reads one crontab: system ones (/etc/crontab, /etc/cron.d) have
// a user field and only root's lines count; root's own crontab has none;
// anacrontab lines are "period delay id command". The crontab itself is
// one of the job's paths: whoever can edit it can add a job.
func cronJob(file, flavor string, lines []string) RootJob {
	j := RootJob{Kind: "cron", Source: file, Paths: []string{file}}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if name, val, ok := envAssignment(l); ok {
			switch name {
			case "PATH": // commands without a path are looked up here
				for _, d := range strings.Split(val, ":") {
					if strings.HasPrefix(d, "/") {
						j.Paths = append(j.Paths, d)
					}
				}
			case "SHELL": // cron runs every command with it
				if strings.HasPrefix(val, "/") {
					j.Paths = append(j.Paths, val)
				}
			}
			continue
		}
		fields := strings.Fields(l)
		n := 5 // minute hour day month weekday
		switch {
		case flavor == "anacron" && strings.HasPrefix(fields[0], "@"):
			n = 3 // @monthly delay id
		case flavor == "anacron":
			n = 3
		case strings.HasPrefix(fields[0], "@"):
			n = 1 // @reboot, @daily, ...
		}
		if flavor == "system" {
			if len(fields) <= n || fields[n] != "root" {
				continue
			}
			n++
		}
		if len(fields) <= n {
			continue
		}
		cmd := cronCommand(strings.Join(fields[n:], " "))
		j.Paths = append(j.Paths, CommandPaths(cmd, false)...)
	}
	j.Paths = dedupe(j.Paths)
	return j
}

// cronCommand cuts a crontab command at the first unescaped %, which cron
// turns into a newline and feeds to the command as input.
func cronCommand(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '%' {
			return s[:i]
		}
	}
	return s
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envAssignment recognizes crontab lines like PATH=/usr/bin:/bin or
// MAILTO = "root".
func envAssignment(l string) (name, val string, ok bool) {
	name, val, ok = strings.Cut(l, "=")
	name = strings.TrimSpace(name)
	if !ok || !envName.MatchString(name) {
		return "", "", false
	}
	return name, strings.Trim(strings.TrimSpace(val), `"'`), true
}

// systemdJobs reads `systemctl show` output: one block of properties per
// service, separated by blank lines. Services that run as another user
// are left out, and so are masked ones: systemd never starts them, and
// their unit file is a link to /dev/null, which anyone can write to.
func systemdJobs(lines []string) []RootJob {
	var jobs []RootJob
	props := map[string][]string{}
	flush := func() {
		defer func() { props = map[string][]string{} }()
		id := first(props["Id"])
		if id == "" || first(props["LoadState"]) == "masked" {
			return
		}
		if u := first(props["User"]); u != "" && u != "root" && u != "0" || first(props["DynamicUser"]) == "yes" {
			// Another user, except for commands marked + or !.
			j := RootJob{Kind: "systemd-privileged", Source: id}
			for _, k := range execKeys {
				for _, v := range props[k+"Ex"] {
					j.Paths = append(j.Paths, execPaths(v, true)...)
				}
			}
			if j.Paths = dedupe(j.Paths); len(j.Paths) > 0 {
				jobs = append(jobs, j)
			}
			return
		}
		j := RootJob{Kind: "systemd", Source: id}
		if p := first(props["FragmentPath"]); strings.HasPrefix(p, "/") {
			j.Paths = append(j.Paths, p)
		}
		for _, p := range strings.Fields(first(props["DropInPaths"])) {
			if strings.HasPrefix(p, "/") {
				j.Paths = append(j.Paths, p)
			}
		}
		for _, k := range execKeys {
			for _, v := range props[k] {
				j.Paths = append(j.Paths, execPaths(v, false)...)
			}
		}
		if j.Paths = dedupe(j.Paths); len(j.Paths) > 0 {
			jobs = append(jobs, j)
		}
	}
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			flush()
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			props[k] = append(props[k], v)
		}
	}
	flush()
	return jobs
}

var execKeys = []string{"ExecStartPre", "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost"}

// execPaths reads one Exec property as systemctl shows it:
// { path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f $EXTRA_OPTS ; ignore_errors=no ; ... }
// or, for the Ex properties, "... ; flags=privileged ; ...". Several
// commands are separated by " } ; { ". With privilegedOnly, only commands
// flagged + (privileged) or ! (no-setuid) count.
func execPaths(v string, privilegedOnly bool) []string {
	var out []string
	for _, cmd := range strings.Split(v, "} ; {") {
		if privilegedOnly {
			_, flags, _ := strings.Cut(cmd, " ; flags=")
			flags, _, _ = strings.Cut(flags, " ;")
			if !strings.Contains(flags, "privileged") && !strings.Contains(flags, "no-setuid") {
				continue
			}
		}
		if _, rest, ok := strings.Cut(cmd, "path="); ok {
			if p, _, _ := strings.Cut(rest, " ;"); strings.HasPrefix(p, "/") {
				out = append(out, strings.TrimSpace(p))
			}
		}
		if _, rest, ok := strings.Cut(cmd, "argv[]="); ok {
			argv := rest
			for _, end := range []string{" ; ignore_errors=", " ; flags="} {
				if i := strings.Index(argv, end); i >= 0 {
					argv = argv[:i]
				}
			}
			out = append(out, CommandPaths(argv, true)...)
		}
	}
	return out
}

// securePath is sudo's secure_path, the PATH for commands run with sudo.
var securePath = regexp.MustCompile(`secure_path\s*=\s*"?([^"\s]+)`)

// securePathJob turns sudo's secure_path into the directories it names.
func securePathJob(sudoers []SudoLine) []RootJob {
	j := RootJob{Kind: "path", Source: "sudo's secure_path"}
	for _, l := range sudoers {
		if !strings.HasPrefix(l.Text, "Defaults") {
			continue
		}
		if m := securePath.FindStringSubmatch(l.Text); m != nil {
			for _, d := range strings.Split(m[1], ":") {
				if strings.HasPrefix(d, "/") {
					j.Paths = append(j.Paths, path.Clean(d))
				}
			}
		}
	}
	if j.Paths = dedupe(j.Paths); len(j.Paths) == 0 {
		return nil
	}
	return []RootJob{j}
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// sudoJobs turns sudo rules into jobs: whoever can change a program a rule
// lets someone run as root can become root through that rule. A command
// with a wildcard counts as the directory it can pick files from.
func sudoJobs(f *Facts) []RootJob {
	users := make([]string, 0, len(f.SudoRights))
	for u := range f.SudoRights {
		users = append(users, u)
	}
	sort.Strings(users)
	var jobs []RootJob
	for _, u := range users {
		j := RootJob{Kind: "sudo", Source: "sudo rule for " + u}
		for _, e := range f.SudoRights[u] {
			if !e.AsRoot() {
				continue
			}
			for _, c := range e.Commands {
				prog, _, _ := strings.Cut(strings.TrimSpace(c), " ")
				if !strings.HasPrefix(prog, "/") {
					continue // ALL, !negations, sudoedit
				}
				if i := strings.IndexAny(prog, "*?["); i >= 0 {
					prog = path.Dir(prog[:i] + "x")
				}
				j.Paths = append(j.Paths, path.Clean(prog))
			}
		}
		if j.Paths = dedupe(j.Paths); len(j.Paths) > 0 {
			jobs = append(jobs, j)
		}
	}
	return jobs
}

// loginFiles are what an account's logins run, relative to its home:
// shell startup files, and ~/.ssh/rc, which sshd runs at every SSH login.
// The home and ~/.ssh themselves are listed too: whoever can write them
// can put any of these files in place.
var loginFiles = []string{"", ".profile", ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
	".zshenv", ".zshrc", ".zprofile", ".zlogin", ".ssh", ".ssh/rc"}

// loginJobs lists the login files of every account that can become root:
// UID 0, a sudo rule that runs any command or one that escapes to a shell
// as root (with or without a password: a changed .bashrc can catch it), or
// a root daemon's socket or a raw disk. Whoever else can change them runs
// commands as that account at its next login, and with that becomes root
// (checked with Debian 13's .bashrc, .profile and ~/.ssh/rc). The files
// that hold its SSH keys count only where sshd has StrictModes off for the
// account: with it on, sshd refuses keys whose file or directories others
// can write. root's own startup files are in rootJobsScript already.
func loginJobs(f *Facts) []RootJob {
	why := map[string]string{}
	for _, p := range f.Passwd {
		if p.UID == 0 {
			why[p.Name] = "UID 0"
		}
	}
	for u, entries := range f.SudoRights {
		for _, e := range entries {
			if _, ok := why[u]; !ok && e.AsRoot() && (e.RootAll() || len(e.Escapes()) > 0) {
				why[u] = "sudo"
			}
		}
	}
	for u, hows := range f.RootDoorRoutes() {
		if _, ok := why[u]; !ok && u != "*" && len(hows) > 0 {
			why[u] = hows[0]
		}
	}
	var jobs []RootJob
	seen := map[string]bool{} // accounts and homes: a UID 0 alias (toor) shares root's
	// root first, so an alias with the same home is the one left out.
	accts := append([]PasswdEntry(nil), f.Passwd...)
	sort.SliceStable(accts, func(a, b int) bool { return accts[a].Name == "root" && accts[b].Name != "root" })
	for _, p := range accts {
		reason, ok := why[p.Name]
		home := path.Clean(p.Home)
		if !ok || seen[p.Name] || seen["home:"+home] || !strings.HasPrefix(p.Home, "/") || home == "/" {
			continue
		}
		seen[p.Name], seen["home:"+home] = true, true
		j := RootJob{Kind: "login", Source: p.Name + " (" + reason + ")", Account: p.Name}
		for _, rel := range loginFiles {
			if home == "/root" && rel != ".ssh/rc" {
				continue // root's startup files are a job of their own (also for UID 0 aliases such as toor)
			}
			j.Paths = append(j.Paths, path.Join(home, rel))
		}
		for _, v := range f.SSHDViews(p.Name) {
			if SSHDFirst(v.Config, "strictmodes") != "no" {
				continue
			}
			for _, k := range strings.Fields(strings.Join(v.Config["authorizedkeysfile"], " ")) {
				if k == "none" {
					continue
				}
				k = strings.NewReplacer("%%", "%", "%h", home, "%u", p.Name, "%U", strconv.Itoa(p.UID)).Replace(k)
				if !strings.HasPrefix(k, "/") {
					k = path.Join(home, k)
				}
				j.Paths = append(j.Paths, path.Dir(path.Clean(k)), path.Clean(k)) // the directory first: it covers the file
			}
		}
		j.Paths = dedupe(j.Paths)
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(a, b int) bool { return jobs[a].Account < jobs[b].Account })
	return jobs
}

// safePath matches paths that can go into a generated script unquoted.
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._+,:@%~=/-]*$`)

// rootPaths lists the distinct shell-safe paths of jobs, at most
// maxRootPaths, and whether some had to be left out.
func rootPaths(jobs []RootJob) (paths []string, truncated bool) {
	seen := map[string]bool{}
	for _, j := range jobs {
		for _, p := range j.Paths {
			if seen[p] || !safePath.MatchString(p) {
				continue
			}
			if len(paths) == maxRootPaths {
				return paths, true
			}
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths, false
}

// pathsScript prints, for every path and each directory above it, and for
// the resolved path of every one that goes through a symlink (itself or a
// directory above it, like /sbin -> usr/sbin) and the directories above
// that, a line "stat|uid|gid|octal mode|type|path", then
// "link|path|resolved" for those and "@@end". For scripts outside the
// package-managed directories it also prints "interp|script|interpreter"
// for their #! line and "calls|script|path" for the programs they run and
// the files they source by absolute path (read on the host by awk, so only
// paths leave it, never script contents), and covers those paths the same
// way. ACL entries of all of them follow (aclsFn). paths must be shell-safe
// (see rootPaths).
func pathsScript(paths []string) string {
	return aclsFn + fmt.Sprintf(`set -f
IFS='
'
paths='%s'
extra=''
for p in $paths; do
  case "$p" in /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*|/usr/lib/*|/usr/lib64/*|/usr/libexec/*|/lib/*|/lib64/*) continue ;; esac
  [ -f "$p" ] || continue
  first=$(head -c 256 "$p" 2>/dev/null | head -n 1)
  case "$first" in '#!'*) ;; *) continue ;; esac
  i=$(echo "${first#??}" | awk '{ sub(/\r$/, ""); if ($1 ~ /\/env$/) { for (k = 2; k <= NF; k++) if ($k !~ /^-/ && $k !~ /=/) { print "env " $k; exit } } else print $1 }')
  case "$i" in 'env '*) i=$(PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin command -v "${i#env }" 2>/dev/null) ;; esac
  case "$i" in /*) echo "interp|$p|$i"; extra="$extra
$i" ;; esac
  calls=$(head -c 65536 "$p" 2>/dev/null | awk 'function ok(p) { return p ~ /^\/[A-Za-z0-9._+,:@%%~=\/-]+$/ }
/^[ \t]*#/ { next }
{
  line = $0
  gsub(/\|\||&&|[;|&]/, "\n", line)
  nc = split(line, cmds, "\n")
  for (c = 1; c <= nc; c++) {
    nw = split(cmds[c], w, /[ \t]+/)
    i = 1
    while (i <= nw && (w[i] == "" || w[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/ || w[i] ~ /^(if|then|do|else|elif|while|until|!|exec|nohup|time|command|[{(])$/)) i++
    if (i > nw) continue
    p = w[i]
    if (p == "." || p == "source") { p = w[i + 1] }
    else {
      b = p; sub(/.*\//, "", b)
      if (b ~ /^(sh|bash|dash|ash|ksh|zsh|python[0-9.]*|perl|php[0-9.]*|ruby|node)$/) {
        if (ok(p)) print p
        for (j = i + 1; j <= nw && w[j] ~ /^-/; j++) {}
        p = w[j]
      }
    }
    if (ok(p)) print p
  }
}' | sort -u | head -n 50)
  for c in $calls; do
    echo "calls|$p|$c"
    extra="$extra
$c"
  done
done
targets=''
for p in $paths $extra; do
  q=$p
  while [ -n "$q" ] && [ ! -L "$q" ]; do q=${q%%/*}; done
  if [ -n "$q" ]; then
    t=$(readlink -f "$p" 2>/dev/null) && [ -n "$t" ] && [ "$t" != "$p" ] && echo "link|$p|$t" && targets="$targets
$t"
  fi
done
all=$({
  echo /
  for p in $paths $extra $targets; do
    q=$p
    while [ -n "$q" ]; do echo "$q"; q=${q%%/*}; done
  done
} | sort -u)
printf '%%s\n' "$all" | tr '\n' '\0' | xargs -0 stat -c 'stat|%%u|%%g|%%a|%%F|%%n' 2>/dev/null
printf '%%s\n' "$all" | acls
echo "@@end"
`, strings.Join(paths, "\n"))
}

// parsePaths reads pathsScript output. Paths that do not exist are simply
// absent. It returns nil maps when the output is incomplete.
func parsePaths(s string) (entries map[string]PathEntry, links, interps map[string]string, calls map[string][]string) {
	entries, links, interps, calls = map[string]PathEntry{}, map[string]string{}, map[string]string{}, map[string][]string{}
	var acls []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "@@end" {
			for p, a := range parseACLs(acls) {
				if e, ok := entries[p]; ok {
					e.ACL = a
					entries[p] = e
				}
			}
			return entries, links, interps, calls
		}
		parts := strings.SplitN(line, "|", 6)
		switch {
		case parts[0] == "acl":
			acls = append(acls, line)
		case parts[0] == "link" && len(parts) >= 3:
			links[parts[1]] = strings.Join(parts[2:], "|")
		case parts[0] == "interp" && len(parts) >= 3:
			interps[parts[1]] = strings.Join(parts[2:], "|")
		case parts[0] == "calls" && len(parts) == 3:
			calls[parts[1]] = append(calls[parts[1]], parts[2])
		case parts[0] == "stat" && len(parts) == 6:
			uid, err1 := strconv.Atoi(parts[1])
			gid, err2 := strconv.Atoi(parts[2])
			mode, err3 := strconv.ParseUint(parts[3], 8, 32)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			typ := "other"
			switch parts[4] {
			case "regular file", "regular empty file":
				typ = "file"
			case "directory":
				typ = "dir"
			case "symbolic link":
				typ = "link"
			}
			entries[parts[5]] = PathEntry{UID: uid, GID: gid, Mode: uint32(mode), Type: typ}
		}
	}
	return nil, nil, nil, nil
}

// Writers returns the accounts other than root that can change p: its
// owner and anyone its permissions let write it, and the same for every
// directory above it, since whoever can write a directory can replace what
// is in it. A sticky directory (like /tmp) protects entries that exist
// from everyone but their owner and the directory's owner. For a symlink,
// the link and its target both count.
func (f *Facts) Writers(p string) []Writer {
	var out []Writer
	seen := map[string]bool{}
	add := func(w Writer) {
		key := w.Account
		if w.Everyone {
			key = "*"
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, w)
		}
	}
	f.chainWriters(p, add)
	if t, ok := f.Links[p]; ok && t != p {
		f.chainWriters(t, add)
	}
	// Whoever can change a script's interpreter controls the script too.
	if i, ok := f.Interpreters[p]; ok {
		through := func(w Writer) {
			w.Through = i
			add(w)
		}
		f.chainWriters(i, through)
		if t, ok := f.Links[i]; ok && t != i {
			f.chainWriters(t, through)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Everyone != out[j].Everyone {
			return out[i].Everyone
		}
		return out[i].Account < out[j].Account
	})
	return out
}

func (f *Facts) chainWriters(p string, add func(Writer)) {
	names, groups := map[int]string{}, map[int]string{}
	for _, e := range f.Passwd {
		if _, dup := names[e.UID]; !dup {
			names[e.UID] = e.Name
		}
	}
	for _, g := range f.Groups {
		groups[g.GID] = g.Name
	}
	accounts := f.accounts()

	childMissing := false
	for i, el := range chain(p) {
		st, ok := f.Paths[el]
		if !ok {
			childMissing = true // whoever can write the parent can create it
			continue
		}
		top := i == 0
		if st.Type == "link" {
			// A symlink's own mode means nothing; whoever can write its
			// directory can replace it (counted next), and its target is
			// checked through the resolved path.
			childMissing = false
			continue
		}
		// Above an existing entry, a sticky directory only lets its own
		// owner replace it (the entry's owner is counted at its own level).
		ownerOnly := !top && st.Type == "dir" && st.Mode&0o1000 != 0 && !childMissing
		childMissing = false
		if st.UID != 0 {
			name, ok := names[st.UID]
			if !ok {
				name = "uid " + strconv.Itoa(st.UID)
			}
			add(Writer{Account: name, Path: el, How: "owner"})
		}
		if ownerOnly {
			continue
		}
		// Accounts that its group, or an ACL entry, lets write it; the
		// others' bits are the next case.
		for _, a := range accounts {
			if a.uid == st.UID {
				continue
			}
			switch via, gid := st.access(a.uid, a.gids, 2); via {
			case viaGroup:
				add(Writer{Account: a.name, Path: el, How: "group " + groups[gid]})
			case viaACLUser:
				add(Writer{Account: a.name, Path: el, How: "an ACL"})
			case viaACLGroup:
				add(Writer{Account: a.name, Path: el, How: "an ACL for group " + groups[gid]})
			}
		}
		if st.Mode&0o002 != 0 {
			add(Writer{Everyone: true, Path: el, How: "world-writable"})
		}
	}
}

// chain lists p and every directory above it, ending with "/".
func chain(p string) []string {
	p = path.Clean(p)
	out := []string{p}
	for p != "/" {
		p = path.Dir(p)
		out = append(out, p)
	}
	return out
}

// writablePaths returns every file root runs or trusts that someone other
// than root can change, in job order. It needs RootJobs and Paths.
func (f *Facts) writablePaths() []WritablePath {
	out := []WritablePath{}
	onPath := map[string]bool{} // a PATH directory is reported once, whichever lists name it
	for _, j := range f.RootJobs {
		// A login or conf job lists a directory and the files in it (a
		// home, /etc/apt/apt.conf.d): a file whose writers its listed
		// directory already has adds nothing.
		reported := map[string]map[string]bool{}
		covered := func(p string, ws []Writer) bool {
			for d := path.Dir(p); ; d = path.Dir(d) {
				if have, ok := reported[d]; ok {
					all := true
					for _, w := range ws {
						all = all && have[w.Account+"|"+strconv.FormatBool(w.Everyone)]
					}
					if all {
						return true
					}
				}
				if d == "/" || d == "." {
					return false
				}
			}
		}
		for _, p := range j.Paths {
			if j.Kind == "path" {
				if onPath[p] {
					continue
				}
				onPath[p] = true
			}
			ws := others(f.Writers(p), j.Account)
			switch {
			case j.Kind == "sudoers":
				ws = sudoersWriters(p, f.Paths[p], ws)
			case j.Kind == "conf" && strings.HasPrefix(j.Source, "polkit"):
				// RHEL and Fedora ship /etc/polkit-1/rules.d owned by
				// polkitd (700): the daemon that decides is as strong as
				// its rules already.
				ws = others(ws, "polkitd")
			}
			if len(ws) > 0 {
				if j.Kind == "login" || j.Kind == "conf" {
					if covered(p, ws) {
						continue
					}
					reported[p] = map[string]bool{}
					for _, w := range ws {
						reported[p][w.Account+"|"+strconv.FormatBool(w.Everyone)] = true
					}
				}
				out = append(out, WritablePath{Kind: j.Kind, Source: j.Source, Path: p, Writers: ws})
			}
			for _, c := range f.Calls[p] {
				if ws := others(f.Writers(c), j.Account); len(ws) > 0 {
					out = append(out, WritablePath{Kind: j.Kind, Source: j.Source, Path: c, CalledBy: p, Writers: ws})
				}
			}
		}
	}
	return out
}

// sudoersWriters keeps the writers of a sudoers file that sudo would still
// read it from: an ACL entry on the file, or its owning group when that is
// root's (sudo accepts group write only for gid 0). sudo refuses a file
// that root does not own, or one a group other than root's can write, and
// whoever can write a directory above it can only put files of their own
// there, which sudo refuses too (checked with sudo 1.9.16 on Debian 13).
func sudoersWriters(p string, e PathEntry, ws []Writer) []Writer {
	if e.GID != 0 {
		return nil // group write (an ACL's mask included) only passes for gid 0
	}
	var out []Writer
	for _, w := range ws {
		if w.Path == p && !w.Everyone && w.How != "owner" {
			out = append(out, w)
		}
	}
	return out
}

// others leaves out account's own access: a login job's account may change
// its own files.
func others(ws []Writer, account string) []Writer {
	if account == "" {
		return ws
	}
	out := ws[:0]
	for _, w := range ws {
		if w.Everyone || w.Account != account {
			out = append(out, w)
		}
	}
	return out
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	out := list[:0]
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
