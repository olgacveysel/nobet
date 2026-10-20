package collect

import (
	"fmt"
	"net/netip"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// sshd's effective config depends on who connects from where once Match
// blocks are involved. The baseline in Facts.SSHD is evaluated for an
// arbitrary account connecting from an address outside any private network
// (probeUser from probeAddr, see sshdScript). When Match lines exist,
// sshd -T -C is run again for each account that can become root and for
// one address per Match Address range, and the differences are kept.

const (
	probeUser     = "nobet-probe" // stands for "any account"; must not exist
	probeAddr     = "192.0.2.1"   // TEST-NET-1: matches no real network
	maxProbeUsers = 20
	maxProbeAddrs = 6
)

// SSHDContext is sshd's effective config for one account (or any account,
// User "") connecting from one address (or anywhere, Addr ""). Only the
// settings that differ from the baseline are kept; a setting that is
// absent here has an empty value.
type SSHDContext struct {
	User    string              `json:"user,omitempty"`
	Addr    string              `json:"addr,omitempty"` // representative client address
	From    string              `json:"from,omitempty"` // the Match Address entry it stands for
	Changes map[string][]string `json:"changes,omitempty"`
}

// SSHDView is the full effective config for one account connecting from
// one place.
type SSHDView struct {
	User   string // "" for any account
	From   string // Match Address entry, "" for anywhere
	Config map[string][]string
}

// SSHDViews returns sshd's effective configs for user ("" for any account):
// from anywhere first, then from each address range that Match blocks
// single out. It returns nil when sshd is not installed, and a single view
// with a nil Config when the config is unknown.
func (f *Facts) SSHDViews(user string) []SSHDView {
	switch {
	case f.NoSSHD():
		return nil
	case f.SSHD == nil:
		return []SSHDView{{User: user}}
	}
	who := ""
	for _, c := range f.SSHDMatch {
		if c.User == user {
			who = user
			break
		}
	}
	views := []SSHDView{{User: user, Config: f.SSHD}}
	for _, c := range f.SSHDMatch {
		if c.User != who {
			continue
		}
		cfg := overlay(f.SSHD, c.Changes)
		if c.Addr == "" {
			views[0].Config = cfg
		} else {
			views = append(views, SSHDView{User: user, From: c.From, Config: cfg})
		}
	}
	return views
}

// SSHDUsers lists the accounts with their own sshd views, after "" for any
// account.
func (f *Facts) SSHDUsers() []string {
	out := []string{""}
	seen := map[string]bool{"": true}
	for _, c := range f.SSHDMatch {
		if !seen[c.User] {
			seen[c.User] = true
			out = append(out, c.User)
		}
	}
	return out
}

func overlay(base, changes map[string][]string) map[string][]string {
	if len(changes) == 0 {
		return base
	}
	m := make(map[string][]string, len(base))
	for k, v := range base {
		m[k] = v
	}
	for k, v := range changes {
		if len(v) == 0 {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// SSHDFirst returns the first value of key in cfg, lowercased.
func SSHDFirst(cfg map[string][]string, key string) string {
	if v := cfg[key]; len(v) > 0 {
		return strings.ToLower(v[0])
	}
	return ""
}

// LoginAllowed applies sshd's DenyUsers, AllowUsers, DenyGroups and
// AllowGroups from cfg to user, in the order sshd does. A user@host
// pattern limits where the user may log in from: it allows the user, but
// does not deny them everywhere. A nil cfg (unknown config) allows.
func (f *Facts) LoginAllowed(cfg map[string][]string, user string) bool {
	matchUser := func(key string, withHost bool) bool {
		for _, p := range sshdPatterns(cfg[key]) {
			u, _, hasHost := strings.Cut(p, "@")
			if hasHost && !withHost {
				continue
			}
			if ok, _ := path.Match(u, user); ok {
				return true
			}
		}
		return false
	}
	groups := f.UserGroups(user)
	matchGroup := func(key string) bool {
		for _, p := range sshdPatterns(cfg[key]) {
			for _, g := range groups {
				if ok, _ := path.Match(p, g); ok {
					return true
				}
			}
		}
		return false
	}
	switch {
	case matchUser("denyusers", false):
		return false
	case len(cfg["allowusers"]) > 0 && !matchUser("allowusers", true):
		return false
	case matchGroup("denygroups"):
		return false
	case len(cfg["allowgroups"]) > 0 && !matchGroup("allowgroups"):
		return false
	}
	return true
}

// sshdPatterns splits sshd -T values, which may hold several
// space-separated patterns per line.
func sshdPatterns(values []string) []string {
	var out []string
	for _, v := range values {
		out = append(out, strings.Fields(v)...)
	}
	return out
}

// splitSSHD separates sshdScript output into the effective config and the
// Match lines found in the config files.
func splitSSHD(out string) (config string, matches []string) {
	config, rest, _ := strings.Cut(out, "@@match\n")
	return config, lines(rest)
}

// probeAddrs picks one client address for each Match Address entry, so
// sshd can be asked what applies from there. It returns the addresses and
// the entries they stand for.
func probeAddrs(matchLines []string) (addrs, from []string) {
	seen := map[string]bool{}
	for _, line := range matchLines {
		fields := strings.Fields(strings.ReplaceAll(line, "=", " "))
		for i := 1; i+1 < len(fields); i++ {
			if !strings.EqualFold(fields[i], "address") {
				continue
			}
			for _, entry := range strings.Split(fields[i+1], ",") {
				a, ok := sampleAddr(entry)
				if !ok || seen[a] || len(addrs) == maxProbeAddrs {
					continue
				}
				seen[a] = true
				addrs, from = append(addrs, a), append(from, entry)
			}
		}
	}
	return addrs, from
}

// sampleAddr returns an address matched by one Match Address entry: a
// CIDR range, an address, or an IPv4 wildcard pattern like 192.168.1.*.
func sampleAddr(entry string) (string, bool) {
	if entry == "" || strings.HasPrefix(entry, "!") {
		return "", false
	}
	if p, err := netip.ParsePrefix(entry); err == nil {
		a := p.Masked().Addr()
		if p.Bits() < a.BitLen() {
			a = a.Next() // a host address, not the network address
		}
		return a.String(), a.IsValid()
	}
	if strings.ContainsAny(entry, "*?") {
		if strings.Contains(entry, ":") {
			return "", false // IPv6 wildcards: no reliable sample
		}
		octets := strings.Split(entry, ".")
		if len(octets) > 4 {
			return "", false
		}
		for i, o := range octets {
			if strings.ContainsAny(o, "*?") {
				o = strings.NewReplacer("*", "1", "?", "1").Replace(o)
			}
			octets[i] = o
		}
		for len(octets) < 4 {
			octets = append(octets, "1")
		}
		entry = strings.Join(octets, ".")
	}
	a, err := netip.ParseAddr(entry)
	if err != nil {
		return "", false
	}
	return a.String(), true
}

var safeUser = regexp.MustCompile(`^[A-Za-z0-9._][A-Za-z0-9._@-]*$`)

// probeUsers lists the accounts whose sshd config matters: those that can
// become root (UID 0, any sudo rule, root-equivalent groups). Names that
// are not safe to put in a shell script are left out.
func probeUsers(f *Facts) []string {
	var uid0, rest []string
	seen := map[string]bool{}
	add := func(list *[]string, u string) {
		if !seen[u] && safeUser.MatchString(u) && u != probeUser {
			seen[u] = true
			*list = append(*list, u)
		}
	}
	for _, p := range f.Passwd {
		if p.UID == 0 {
			add(&uid0, p.Name)
		}
	}
	for u, entries := range f.SudoRights {
		if len(entries) > 0 {
			add(&rest, u)
		}
	}
	for _, g := range RootEquivalentGroups {
		for _, u := range f.GroupMembers(g) {
			add(&rest, u)
		}
	}
	sort.Strings(rest)
	out := append(uid0, rest...)
	if len(out) > maxProbeUsers {
		out = out[:maxProbeUsers]
	}
	return out
}

// sshdMatchScript asks sshd for its effective config for every account
// and address combination. users and addrs must be shell-safe (see
// probeUsers and sampleAddr).
func sshdMatchScript(users, addrs []string, port int) string {
	return fmt.Sprintf(`PATH=$PATH:/usr/sbin:/sbin
%sopts=$(sshd_opts)
set -f
for u in %s %s; do
  for a in %s %s; do
    echo "@@ctx $u $a"
    sshd -T -C "user=$u,host=nobet.invalid,addr=$a,laddr=192.0.2.2,lport=%d" $opts 2>&1 || echo "@@failed"
  done
done
true
`, sshdOptsFunc, probeUser, strings.Join(users, " "), probeAddr, strings.Join(addrs, " "), port)
}

// parseSSHDMatch reads sshdMatchScript output into contexts that hold the
// differences from base. from maps probe addresses to their Match entries.
// It reports the first evaluation that failed, if any.
func parseSSHDMatch(out string, base map[string][]string, from map[string]string) ([]SSHDContext, error) {
	ctxs := []SSHDContext{}
	var cur *SSHDContext
	var body []string
	var failed error
	flush := func() {
		if cur == nil {
			return
		}
		text := strings.Join(body, "\n")
		if strings.Contains(text, "@@failed") {
			if failed == nil {
				msg := strings.TrimSpace(strings.ReplaceAll(text, "@@failed", ""))
				failed = fmt.Errorf("sshd -T -C user=%s,addr=%s: %s", orAny(cur.User), cur.Addr, msg)
			}
		} else {
			cur.Changes = diffConfig(base, parseSSHD(text))
			ctxs = append(ctxs, *cur)
		}
		cur, body = nil, nil
	}
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(line, "@@ctx "); ok {
			flush()
			user, addr, _ := strings.Cut(rest, " ")
			c := SSHDContext{User: user, Addr: addr, From: from[addr]}
			if user == probeUser {
				c.User = ""
			}
			if addr == probeAddr {
				c.Addr, c.From = "", ""
			}
			cur = &c
			continue
		}
		body = append(body, line)
	}
	flush()
	return ctxs, failed
}

func orAny(user string) string {
	if user == "" {
		return probeUser
	}
	return user
}

// diffConfig returns the settings whose values differ between base and
// cfg; a setting missing from cfg maps to an empty list.
func diffConfig(base, cfg map[string][]string) map[string][]string {
	d := map[string][]string{}
	for k, v := range cfg {
		if strings.Join(v, "\n") != strings.Join(base[k], "\n") {
			d[k] = v
		}
	}
	for k := range base {
		if _, ok := cfg[k]; !ok {
			d[k] = []string{}
		}
	}
	if len(d) == 0 {
		return nil
	}
	return d
}

// sshdPort returns the first port sshd listens on, or 22.
func sshdPort(cfg map[string][]string) int {
	if p, err := strconv.Atoi(SSHDFirst(cfg, "port")); err == nil && p > 0 {
		return p
	}
	return 22
}
