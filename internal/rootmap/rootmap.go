// Package rootmap answers "who can become root, on which host, and how?"
// across a fleet. It combines each host's authorized SSH keys with the
// routes to root available to each account (UID 0 login, sudo ALL,
// root-equivalent groups), and groups the result by SSH key, so one key
// that opens root on many hosts stands out.
package rootmap

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

// Route is one way an account can become root.
type Route struct {
	Via           string `json:"via"`
	NeedsPassword bool   `json:"needs_password"`
}

// Grant is root access that a key gives on one host, as one account.
type Grant struct {
	Host       string  `json:"host"`
	User       string  `json:"user"`
	Routes     []Route `json:"routes"`
	Restricted string  `json:"restricted,omitempty"` // forced command or source restriction on the key
}

// Key is an SSH key that leads to root on at least one host.
type Key struct {
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Comments    []string `json:"comments,omitempty"`
	Grants      []Grant  `json:"grants"`
}

// Hosts returns the number of distinct hosts this key reaches root on.
func (k Key) Hosts() int {
	seen := map[string]bool{}
	for _, g := range k.Grants {
		seen[g.Host] = true
	}
	return len(seen)
}

// Account is a root-capable account that cannot be reached with an SSH
// key: it has none, or sshd does not let it log in with one.
type Account struct {
	Host   string  `json:"host"`
	User   string  `json:"user"`
	Routes []Route `json:"routes"`
}

// Gap is something that kept the map for a host from being complete.
type Gap struct {
	Host   string `json:"host"`
	Reason string `json:"reason"`
}

// Map is the fleet-wide result.
type Map struct {
	Keys         []Key     `json:"keys"`
	KeylessUsers []Account `json:"accounts_without_keys"`
	Gaps         []Gap     `json:"incomplete"`
}

// Build computes the map from scan results.
func Build(results []scan.HostResult) Map {
	m := Map{Keys: []Key{}, KeylessUsers: []Account{}, Gaps: []Gap{}}
	keys := map[string]*Key{}

	for _, r := range results {
		if r.Error != "" {
			m.Gaps = append(m.Gaps, Gap{Host: r.Host, Reason: "not scanned: " + r.Error})
			continue
		}
		f := r.Facts
		if f == nil {
			continue
		}
		routes, gaps := Routes(f)
		for _, g := range gaps {
			m.Gaps = append(m.Gaps, Gap{Host: r.Host, Reason: g})
		}
		if f.AuthKeys == nil {
			m.Gaps = append(m.Gaps, Gap{Host: r.Host, Reason: "authorized_keys unreadable (needs root or passwordless sudo)"})
		}

		uid0 := map[string]bool{}
		for _, p := range f.Passwd {
			uid0[p.Name] = p.UID == 0
		}
		keysByUser := map[string][]collect.AuthKey{}
		for _, k := range f.AuthKeys {
			keysByUser[k.User] = append(keysByUser[k.User], k)
		}

		users := make([]string, 0, len(routes))
		for u := range routes {
			users = append(users, u)
		}
		sort.Strings(users)

		for _, user := range users {
			rs := routes[user]
			ks := keysByUser[user]
			from, ok := keyLogin(f, user)
			if len(ks) == 0 || !ok {
				if f.AuthKeys != nil {
					m.KeylessUsers = append(m.KeylessUsers, Account{Host: r.Host, User: user, Routes: rs})
				}
				continue
			}
			for _, ak := range ks {
				restricted := restriction(ak.Options)
				if from != "" && !uid0[user] { // UID 0 routes already say where from
					restricted = join(restricted, "sshd allows it only "+from)
				}
				k := keys[ak.Fingerprint]
				if k == nil {
					k = &Key{Fingerprint: ak.Fingerprint, Type: ak.Type}
					keys[ak.Fingerprint] = k
				}
				if ak.Comment != "" && !contains(k.Comments, ak.Comment) {
					k.Comments = append(k.Comments, ak.Comment)
				}
				k.Grants = append(k.Grants, Grant{Host: r.Host, User: user, Routes: rs, Restricted: restricted})
			}
		}
	}

	for _, k := range keys {
		m.Keys = append(m.Keys, *k)
	}
	sort.Slice(m.Keys, func(i, j int) bool {
		if hi, hj := m.Keys[i].Hosts(), m.Keys[j].Hosts(); hi != hj {
			return hi > hj
		}
		return m.Keys[i].Fingerprint < m.Keys[j].Fingerprint
	})
	return m
}

// Routes returns, per account, the ways it can become root, plus notes
// about data that was missing.
func Routes(f *collect.Facts) (map[string][]Route, []string) {
	routes := map[string][]Route{}
	var gaps []string
	add := func(user string, r Route) { routes[user] = append(routes[user], r) }
	// addFrom adds a route that exists in some sshd views, noting where
	// when it is not available from anywhere.
	addFrom := func(user, via string, needsPassword bool, from []string) {
		if len(from) == 0 {
			return
		}
		if w := where(from); w != "" {
			via += " " + w
		}
		add(user, Route{Via: via, NeedsPassword: needsPassword})
	}

	if f.SSHD == nil {
		gaps = append(gaps, "sshd config unknown; assuming root may log in with a key")
	}
	if e := f.Errors["sshd-match"]; e != "" {
		gaps = append(gaps, "sshd Match blocks could not be evaluated, so only the global settings were used ("+e+")")
	}
	if f.Passwd == nil {
		gaps = append(gaps, "accounts unknown (could not read /etc/passwd)")
	}
	if f.Shadow == nil && f.Privileged() {
		gaps = append(gaps, "password states unknown; routes that need a password are listed even for locked accounts")
	}
	if v := collect.SSHDFirst(f.SSHD, "authorizedkeyscommand"); v != "" && v != "none" {
		gaps = append(gaps, "sshd also takes keys from AuthorizedKeysCommand ("+v+"); those keys are not listed")
	}
	if v := collect.SSHDFirst(f.SSHD, "trustedusercakeys"); v != "" && v != "none" {
		gaps = append(gaps, "sshd accepts user certificates signed by the CA in "+v+"; certificate holders are not listed")
	}

	// Direct login to a UID 0 account. PermitRootLogin applies to every
	// UID 0 account, not only "root".
	uid0 := map[string]bool{}
	for _, p := range f.Passwd {
		if p.UID != 0 {
			continue
		}
		uid0[p.Name] = true
		pw, expired, _ := f.Password(p.Name)
		if expired {
			continue
		}
		var keyFrom, pwFrom, emptyFrom, forcedFrom []string
		for _, v := range f.SSHDViews(p.Name) {
			prl := collect.SSHDFirst(v.Config, "permitrootlogin")
			if prl == "no" || !f.LoginAllowed(v.Config, p.Name) {
				continue
			}
			if prl == "forced-commands-only" {
				forcedFrom = append(forcedFrom, v.From)
				continue
			}
			if pubkeyAuth(v.Config) {
				keyFrom = append(keyFrom, v.From)
			}
			if prl == "yes" && collect.SSHDFirst(v.Config, "passwordauthentication") == "yes" {
				switch pw {
				case collect.PasswordLocked:
				case collect.PasswordEmpty:
					if collect.SSHDFirst(v.Config, "permitemptypasswords") == "yes" {
						emptyFrom = append(emptyFrom, v.From)
					}
				default:
					pwFrom = append(pwFrom, v.From)
				}
			}
		}
		addFrom(p.Name, "UID 0 login, forced commands only", false, forcedFrom)
		addFrom(p.Name, "UID 0 login", false, keyFrom)
		addFrom(p.Name, "UID 0 login with empty password", false, emptyFrom)
		addFrom(p.Name, "UID 0 login with password", true, pwFrom)
	}

	if f.SudoRights == nil {
		gaps = append(gaps, "sudo rights unknown (needs root or passwordless sudo)")
	} else {
		for user, entries := range f.SudoRights {
			if uid0[user] {
				continue // already root
			}
			pw, expired, _ := f.Password(user)
			if expired {
				continue // sudo's PAM account check refuses expired accounts
			}
			authFor := func(cmd string) string { return f.SudoAuthFor(user, "root", cmd) }
			if r, ok := sudoRoute(entries, pw, authFor); ok {
				add(user, r)
			}
		}
	}

	if f.Groups == nil {
		gaps = append(gaps, "group membership unknown")
	} else {
		for _, g := range collect.RootEquivalentGroups {
			for _, u := range f.GroupMembers(g) {
				if !uid0[u] {
					add(u, Route{Via: g + " group"})
				}
			}
		}
	}
	return routes, gaps
}

// keyLogin reports whether user can log in over SSH with a key, and from
// where when sshd allows it only from some addresses ("" for anywhere).
func keyLogin(f *collect.Facts, user string) (from string, ok bool) {
	if _, expired, _ := f.Password(user); expired {
		return "", false
	}
	isRoot := false
	for _, p := range f.Passwd {
		if p.Name == user && p.UID == 0 {
			isRoot = true
		}
	}
	var froms []string
	for _, v := range f.SSHDViews(user) {
		if isRoot && collect.SSHDFirst(v.Config, "permitrootlogin") == "no" {
			continue
		}
		if pubkeyAuth(v.Config) && f.LoginAllowed(v.Config, user) {
			froms = append(froms, v.From)
		}
	}
	return where(froms), len(froms) > 0
}

// pubkeyAuth reports whether an sshd config accepts key logins. A nil
// (unknown) config counts as yes.
func pubkeyAuth(cfg map[string][]string) bool {
	return collect.SSHDFirst(cfg, "pubkeyauthentication") != "no"
}

// where describes the sshd views a route exists in: "" when one of them
// is "from anywhere", otherwise "from <Match Address entries>".
func where(from []string) string {
	for _, f := range from {
		if f == "" {
			return ""
		}
	}
	if len(from) == 0 {
		return ""
	}
	return "from " + strings.Join(from, ", ")
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + ", " + b
}

// sudoRoute returns the most direct sudo route to root among a user's
// rules: no password needed beats password, then sudo ALL beats a limited
// rule that escapes to a shell. authFor says whose password sudo asks for
// a command ("ALL" for any): root's (rootpw, targetpw) is no route, since
// knowing it already makes you root. pw is the user's password state (""
// if unknown): a locked password makes rules that ask for it useless, and
// an empty one makes them free (pam_unix nullok).
func sudoRoute(entries []collect.SudoEntry, pw string, authFor func(cmd string) string) (Route, bool) {
	var best Route
	rank := -1
	consider := func(via string, base int, nopasswd bool, cmd string) {
		route := Route{Via: via + ", no password"}
		switch auth := authFor(cmd); {
		case nopasswd || auth == collect.SudoAuthNone:
		case auth == collect.SudoAuthTarget, pw == collect.PasswordLocked:
			return
		case pw == collect.PasswordEmpty:
			route = Route{Via: via + ", empty password"}
		default:
			route = Route{Via: via + ", password required", NeedsPassword: true}
		}
		r := base
		if !route.NeedsPassword {
			r += 2
		}
		if r > rank {
			best, rank = route, r
		}
	}
	for _, e := range entries {
		if e.RootAll() {
			consider("sudo ALL", 1, e.NoPasswd, "ALL")
			continue
		}
		for _, c := range e.Escapes() {
			consider("sudo "+c+" (shell escape)", 0, e.NoPasswd, c)
		}
	}
	return best, rank >= 0
}

// restriction describes authorized_keys options that limit what a key can do.
func restriction(options []string) string {
	var out []string
	for _, o := range options {
		name, val, _ := strings.Cut(o, "=")
		switch strings.ToLower(name) {
		case "command":
			out = append(out, "forced command "+val)
		case "from":
			out = append(out, "only from "+val)
		case "restrict":
			out = append(out, "restrict")
		}
	}
	return strings.Join(out, ", ")
}

// WriteText renders the map for humans.
func (m Map) WriteText(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()

	fmt.Fprintln(tw, "ROOT ACCESS BY SSH KEY")
	if len(m.Keys) == 0 {
		fmt.Fprintln(tw, "  No SSH key leads to root on the scanned hosts.")
	}
	for _, k := range m.Keys {
		label := k.Fingerprint + "  " + strings.TrimPrefix(k.Type, "ssh-")
		if len(k.Comments) > 0 {
			label += "  " + strings.Join(k.Comments, ", ")
		}
		fmt.Fprintf(tw, "\n%s\n", label)
		fmt.Fprintf(tw, "  root on %d host(s):\n", k.Hosts())
		for _, g := range k.Grants {
			line := fmt.Sprintf("    %s\tas %s\tvia %s", g.Host, g.User, routeText(g.Routes))
			if g.Restricted != "" {
				line += "  [" + g.Restricted + "]"
			}
			fmt.Fprintln(tw, line)
		}
	}

	if len(m.KeylessUsers) > 0 {
		fmt.Fprintln(tw, "\nROOT-CAPABLE ACCOUNTS WITHOUT SSH KEY ACCESS")
		for _, a := range m.KeylessUsers {
			fmt.Fprintf(tw, "    %s\t%s\tvia %s\n", a.Host, a.User, routeText(a.Routes))
		}
	}

	if len(m.Gaps) > 0 {
		fmt.Fprintln(tw, "\nINCOMPLETE")
		for _, g := range m.Gaps {
			fmt.Fprintf(tw, "    %s\t%s\n", g.Host, g.Reason)
		}
	}
}

func routeText(rs []Route) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.Via
	}
	return strings.Join(parts, "; ")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
