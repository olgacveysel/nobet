package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/fleet"
	"github.com/olgacveysel/nobet/internal/inventory"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/sshconf"
	"github.com/olgacveysel/nobet/internal/transport"
)

// targets holds the flags that choose what to scan, shared by every
// command that scans hosts.
type targets struct {
	invPath     *string
	groups      *string
	local       *bool
	concurrency *int
	timeout     *time.Duration
	cmdTimeout  *time.Duration
	user        *string
	identity    *string
	knownHosts  *string
	noSSHConfig *bool
	sshConfig   *string

	hosts   []fleet.Target
	doLocal bool
	opts    transport.SSHOptions
}

const targetUsage = `  nobet %[1]s [flags]                          this machine (use sudo for full results)
  nobet %[1]s [flags] [user@]host[:port] ...   remote hosts over SSH
  nobet %[1]s [flags] -i hosts.txt             hosts from an inventory file

With no hosts and no -i, the local machine is scanned. Add -local to include
it alongside remote hosts. Flags must come before host arguments.
`

func addTargetFlags(fs *flag.FlagSet) *targets {
	t := &targets{
		invPath:     fs.String("i", "", "inventory file: one [user@]host[:port] per line, an Ansible INI inventory, or the JSON of ansible-inventory --list"),
		groups:      fs.String("group", "", "only these Ansible inventory groups (comma-separated; children included)"),
		local:       fs.Bool("local", false, "also scan this machine when scanning remote hosts"),
		concurrency: fs.Int("c", 10, "number of remote hosts to scan in parallel"),
		timeout:     fs.Duration("timeout", 10*time.Second, "SSH connect timeout"),
		cmdTimeout:  fs.Duration("cmd-timeout", 60*time.Second, "timeout for each command"),
		user:        fs.String("u", "", "default SSH user (default: your local username)"),
		identity:    fs.String("identity", "", "private key file (default: ~/.ssh/id_ed25519, id_ecdsa, id_rsa)"),
		knownHosts:  fs.String("known-hosts", "", "known_hosts file (default: ~/.ssh/known_hosts)"),
		noSSHConfig: fs.Bool("no-ssh-config", false, "ignore ~/.ssh/config (aliases, users, ports, keys, ProxyJump)"),
		sshConfig:   fs.String("ssh-config", "", "read this SSH config file instead of ~/.ssh/config and /etc/ssh/ssh_config"),
	}
	fs.StringVar(t.sshConfig, "F", "", "shorthand for -ssh-config")
	fs.BoolVar(t.local, "l", false, "shorthand for -local")
	fs.DurationVar(t.timeout, "t", 10*time.Second, "shorthand for -timeout")
	return t
}

// resolve reads the inventory and host arguments after fs.Parse. It
// prints the problem and returns false on error.
func (t *targets) resolve(fs *flag.FlagSet) bool {
	// An empty default user lets ~/.ssh/config supply one; the local
	// username is the last resort (see sshconf.Resolve).
	defUser := *t.user
	var hosts []inventory.Host
	if *t.groups != "" && *t.invPath == "" {
		fmt.Fprintln(os.Stderr, "nobet: -group needs an Ansible inventory (-i)")
		return false
	}
	if *t.invPath != "" {
		var groups []string
		for _, g := range strings.Split(*t.groups, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups = append(groups, g)
			}
		}
		hs, skipped, err := inventory.Load(*t.invPath, defUser, groups)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet:", err)
			return false
		}
		if len(skipped) > 0 {
			fmt.Fprintf(os.Stderr, "nobet: note: skipping %s (ansible_connection=local; use -local to scan this machine)\n", strings.Join(skipped, ", "))
		}
		if len(hs) == 0 && !*t.local {
			fmt.Fprintf(os.Stderr, "nobet: %s contains no hosts\n", *t.invPath)
			return false
		}
		hosts = hs
	}
	for _, arg := range fs.Args() {
		h, err := inventory.Parse(arg, defUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet:", err)
			return false
		}
		hosts = append(hosts, h)
	}
	t.doLocal = *t.local || len(hosts) == 0

	var lookup sshconf.Lookup = sshconf.System{}
	if *t.noSSHConfig {
		lookup = sshconf.None{}
	} else if *t.sshConfig != "" {
		f, err := sshconf.LoadFile(*t.sshConfig)
		if err != nil {
			fmt.Fprintln(os.Stderr, "nobet: SSH config:", err)
			return false
		}
		lookup = f
	} else if len(hosts) > 0 {
		if err := sshconf.Check(); err != nil {
			fmt.Fprintf(os.Stderr, "nobet: warning: could not parse your SSH config (%v); continuing without it\n", err)
			lookup = sshconf.None{}
		}
	}
	for _, h := range hosts {
		st, err := sshconf.Resolve(h, lookup)
		t.hosts = append(t.hosts, fleet.Target{Name: h.Name, SSH: st, Err: err})
	}

	t.opts = transport.DefaultSSHOptions()
	t.opts.Timeout = *t.timeout
	t.opts.CommandTimeout = *t.cmdTimeout
	if *t.identity != "" {
		t.opts.KeyFiles = []string{*t.identity}
	}
	if *t.knownHosts != "" {
		t.opts.KnownHostsFile = *t.knownHosts
	}
	return true
}

// only keeps the targets with these names (the local machine as
// scan.LocalName()) and returns the names that matched none.
func (t *targets) only(names []string) (unknown []string) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	found := map[string]bool{}
	if t.doLocal && want[scan.LocalName()] {
		found[scan.LocalName()] = true
	} else {
		t.doLocal = false
	}
	var keep []fleet.Target
	for _, h := range t.hosts {
		if want[h.Name] {
			keep = append(keep, h)
			found[h.Name] = true
		}
	}
	t.hosts = keep
	for _, n := range names {
		if !found[n] {
			unknown = append(unknown, n)
		}
	}
	return unknown
}

// names lists every target in scan order: local machine first.
func (t *targets) names() []string {
	var out []string
	if t.doLocal {
		out = append(out, scan.LocalName())
	}
	for _, h := range t.hosts {
		out = append(out, h.Name)
	}
	return out
}

// run scans every target. onDone may be nil; its index matches names().
func (t *targets) run(onDone func(i int, r scan.HostResult)) []scan.HostResult {
	var results []scan.HostResult
	offset := 0
	if t.doLocal {
		r := fleet.Local(*t.cmdTimeout)
		results = append(results, r)
		if onDone != nil {
			onDone(0, r)
		}
		offset = 1
	}
	if len(t.hosts) > 0 {
		var cb func(int, scan.HostResult)
		if onDone != nil {
			cb = func(i int, r scan.HostResult) { onDone(i+offset, r) }
		}
		results = append(results, fleet.Remote(t.hosts, t.opts, *t.concurrency, cb)...)
	}
	return results
}

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
