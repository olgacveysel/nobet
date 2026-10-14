package collect

import (
	"path"
	"strings"
)

// Programs that turn a limited sudo rule into full root, after GTFOBins
// (https://gtfobins.github.io, "Sudo"). Interactive programs escape even
// with fixed arguments (an editor's :!sh, a pager's !sh); the others need
// the attacker to choose the arguments.
var (
	escapeShells = set("sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox", "su")
	// Spawn a shell even with fixed arguments.
	escapeInteractive = set("vi", "vim", "view", "nvim", "nano", "pico", "emacs", "ed", "less", "more", "man",
		"journalctl", "mysql", "mariadb", "psql", "sqlite3", "ftp", "gdb", "top", "script", "screen", "tmux")
	// Spawn a shell or run commands when the arguments are free.
	escapeWithArgs = set("python", "python2", "python3", "perl", "ruby", "lua", "php", "node", "irb", "awk", "gawk",
		"mawk", "nawk", "find", "env", "xargs", "nice", "timeout", "nohup", "stdbuf", "strace", "ltrace", "taskset",
		"ionice", "setsid", "flock", "watch", "tar", "zip", "rsync", "git", "ssh", "scp", "docker", "podman", "kubectl",
		"systemctl", "service", "apt", "apt-get", "dpkg", "rpm", "yum", "dnf", "pip", "pip3", "npm", "gem", "make",
		"gcc", "socat", "nmap", "tcpdump", "sed", "openssl", "crontab", "mount", "chroot", "unshare", "nsenter",
		"ansible-playbook", "busctl", "run-parts", "start-stop-daemon")
	// Write arbitrary files as root (sudoers, cron, authorized_keys) when
	// the arguments are free. NOEXEC does not stop these.
	escapeWrite = set("cp", "mv", "dd", "tee", "install", "chmod", "chown", "ln", "wget", "curl", "rsync", "tar",
		"zip", "unzip", "sed", "openssl", "base64")
)

func set(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// AsRoot reports whether the rule runs commands as root.
func (e SudoEntry) AsRoot() bool {
	runAs := strings.TrimSpace(strings.SplitN(e.RunAs, ":", 2)[0])
	return runAs == "" || runAs == "ALL" || runAs == "root"
}

// Escapes returns the commands in a limited rule that can be used to get
// a root shell or to write any file as root. It returns nil for rules
// that grant ALL, which RootAll already covers.
func (e SudoEntry) Escapes() []string {
	if !e.AsRoot() || e.RootAll() {
		return nil
	}
	var out []string
	for _, c := range e.Commands {
		if strings.HasPrefix(c, "!") {
			continue
		}
		if escapes(c, e.NoExec) {
			out = append(out, c)
		}
	}
	return out
}

// escapes reports whether one sudo command spec escapes to root.
func escapes(cmd string, noexec bool) bool {
	bin, args, _ := strings.Cut(strings.TrimSpace(cmd), " ")
	args = strings.TrimSpace(args)
	if bin == "sudoedit" {
		return false // edits as the invoking user, then copies back
	}
	name := path.Base(bin)
	if strings.ContainsAny(name, "*?[") {
		return true // a wildcard in the program name matches shells too
	}
	if strings.HasPrefix(name, "python") || strings.HasPrefix(name, "perl") || strings.HasPrefix(name, "php") {
		name = strings.TrimRight(name, "0123456789.")
	}
	// No arguments in sudoers means any arguments; a wildcard lets the
	// user add their own.
	freeArgs := args == "" || strings.ContainsAny(args, "*?")
	if args == `""` {
		freeArgs = false // explicitly no arguments
	}

	if freeArgs && escapeWrite[name] {
		return true
	}
	if noexec {
		return false // the remaining escapes need to exec a shell
	}
	return escapeShells[name] || escapeInteractive[name] || (freeArgs && escapeWithArgs[name])
}
