// Package drift compares two snapshots of the same host and reports what
// changed: new routes to root, new SSH keys, accounts, sshd settings,
// listening ports and findings.
package drift

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/store"
)

// Kind of change.
const (
	Added   = "added"
	Removed = "removed"
	Changed = "changed"
)

// Change is one difference between two scans of a host.
type Change struct {
	Kind string `json:"kind"`
	Area string `json:"area"` // root, key, account, group, suid, sshd, firewall, port, finding, updates, kernel, os
	What string `json:"what"`
}

// HostDrift is every change on one host between two scans.
type HostDrift struct {
	Host    string    `json:"host"`
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Changes []Change  `json:"changes"`
}

// areaOrder sorts the most security-relevant changes first.
var areaOrder = map[string]int{"root": 0, "key": 1, "account": 2, "group": 3, "suid": 4, "sshd": 5, "firewall": 6, "port": 7, "finding": 8, "updates": 9, "kernel": 10, "os": 11}

// sshdKeys are the sshd settings whose changes are reported.
var sshdKeys = []string{
	"permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication",
	"permitemptypasswords", "pubkeyauthentication", "x11forwarding",
	"port", "allowusers", "allowgroups", "denyusers", "denygroups", "authorizedkeysfile",
}

// Compare returns what changed on a host between old and cur.
func Compare(old, cur store.HostSnapshot) HostDrift {
	d := HostDrift{Host: cur.Host, From: old.Time, To: cur.Time}
	add := func(kind, area, what string) { d.Changes = append(d.Changes, Change{kind, area, what}) }
	set := func(area string, before, after []string) {
		a, r := diffSets(before, after)
		for _, x := range a {
			add(Added, area, x)
		}
		for _, x := range r {
			add(Removed, area, x)
		}
	}

	of, nf := old.Facts, cur.Facts
	if of != nil && nf != nil {
		// Root routes and keys are only complete with privilege on both
		// sides; comparing partial data would invent changes.
		if of.Privileged() && nf.Privileged() {
			o, n := of, nf
			if (of.RootWritable == nil) != (nf.RootWritable == nil) {
				// Only one scan checked the files root runs (an older nobet,
				// or a listing that failed): leave the routes through them out.
				oc, nc := *of, *nf
				oc.RootWritable, nc.RootWritable = nil, nil
				o, n = &oc, &nc
			}
			set("root", routes(o), routes(n))
			if of.AuthKeys != nil && nf.AuthKeys != nil {
				set("key", keys(of), keys(nf))
			}
		}
		if of.Passwd != nil && nf.Passwd != nil {
			set("account", accounts(of), accounts(nf))
		}
		if of.Groups != nil && nf.Groups != nil {
			set("group", memberships(of), memberships(nf))
		}
		if of.Shadow != nil && nf.Shadow != nil {
			for _, s := range nf.Shadow {
				pw, expired, ok := of.Password(s.User)
				if !ok {
					continue // a new account, reported above
				}
				if pw != s.Password {
					add(Changed, "account", fmt.Sprintf("%s password: %s → %s", s.User, pw, s.Password))
				}
				if expired != s.Expired {
					add(Changed, "account", fmt.Sprintf("%s expired: %v → %v", s.User, expired, s.Expired))
				}
			}
		}
		if of.SSHD != nil && nf.SSHD != nil {
			for _, k := range sshdKeys {
				a, b := strings.Join(of.SSHD[k], " "), strings.Join(nf.SSHD[k], " ")
				if a != b {
					add(Changed, "sshd", fmt.Sprintf("%s: %s → %s", k, orNone(a), orNone(b)))
				}
			}
		}
		if of.SUID != nil && nf.SUID != nil {
			set("suid", suids(of), suids(nf))
		}
		if of.Firewall != nil && nf.Firewall != nil && of.Firewall.Active() != nf.Firewall.Active() {
			add(Changed, "firewall", fmt.Sprintf("incoming filtering: %s → %s", onOff(of.Firewall.Active()), onOff(nf.Firewall.Active())))
		}
		if of.Listeners != nil && nf.Listeners != nil {
			set("port", ports(of), ports(nf))
		}
		if a, b := secCount(of), secCount(nf); a >= 0 && b >= 0 && a != b {
			what := "pending security updates"
			if nf.Updates.Manager == "apk" {
				what = "pending updates" // apk does not label security fixes
			}
			add(Changed, "updates", fmt.Sprintf("%s: %d → %d", what, a, b))
		}
		if of.Reboot != nil && nf.Reboot != nil && of.Reboot.Running != nf.Reboot.Running {
			add(Changed, "kernel", fmt.Sprintf("running kernel: %s → %s", of.Reboot.Running, nf.Reboot.Running))
		}
		if a, b := of.OSRelease["PRETTY_NAME"], nf.OSRelease["PRETTY_NAME"]; a != "" && b != "" && a != b {
			add(Changed, "os", fmt.Sprintf("%s → %s", a, b))
		}
	}
	set("finding", findings(old), findings(cur))

	sort.SliceStable(d.Changes, func(i, j int) bool {
		return areaOrder[d.Changes[i].Area] < areaOrder[d.Changes[j].Area]
	})
	return d
}

// Latest compares the two most recent successful scans of every host in
// the history at dir. Hosts with a single successful scan are returned in
// once, hosts without any in never.
func Latest(dir string) (drifts []HostDrift, once, never []string, err error) {
	recent, hosts, err := store.Recent(dir, 2)
	for _, h := range hosts {
		switch r := recent[h]; len(r) {
		case 0:
			never = append(never, h)
		case 1:
			once = append(once, h)
		default:
			drifts = append(drifts, Compare(r[0], r[1]))
		}
	}
	return drifts, once, never, err
}

// WriteText renders drifts for humans.
func WriteText(w io.Writer, drifts []HostDrift) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	for _, d := range drifts {
		fmt.Fprintf(tw, "\n== %s  (%s → %s)\n", d.Host, d.From.Local().Format("2006-01-02 15:04"), d.To.Local().Format("2006-01-02 15:04"))
		if len(d.Changes) == 0 {
			fmt.Fprintln(tw, "  no changes")
			continue
		}
		for _, c := range d.Changes {
			sign := map[string]string{Added: "+", Removed: "-", Changed: "~"}[c.Kind]
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", sign, c.Area, c.What)
		}
	}
}

// Count returns the total number of changes and of hosts with changes.
func Count(drifts []HostDrift) (changes, hosts int) {
	for _, d := range drifts {
		if len(d.Changes) > 0 {
			hosts++
			changes += len(d.Changes)
		}
	}
	return changes, hosts
}

func routes(f *collect.Facts) []string {
	rs, _ := rootmap.Routes(f)
	var out []string
	for user, list := range rs {
		for _, r := range list {
			out = append(out, user+" via "+r.Via)
		}
	}
	return out
}

func keys(f *collect.Facts) []string {
	var out []string
	for _, k := range f.AuthKeys {
		s := k.User + ": " + k.Fingerprint
		if k.Comment != "" {
			s += " " + k.Comment
		}
		out = append(out, s)
	}
	return out
}

func accounts(f *collect.Facts) []string {
	var out []string
	for _, p := range f.Passwd {
		out = append(out, fmt.Sprintf("%s (uid %d, %s)", p.Name, p.UID, p.Shell))
	}
	return out
}

// memberships lists "user in group" for every supplementary group member.
func memberships(f *collect.Facts) []string {
	var out []string
	for _, g := range f.Groups {
		for _, m := range g.Members {
			out = append(out, m+" in "+g.Name)
		}
	}
	return out
}

func ports(f *collect.Facts) []string {
	var out []string
	for _, l := range f.Listeners {
		addr := l.Addr
		if strings.Contains(addr, ":") {
			addr = "[" + addr + "]"
		}
		out = append(out, l.Proto+" "+addr+":"+strconv.Itoa(l.Port))
	}
	return out
}

func findings(h store.HostSnapshot) []string {
	var out []string
	for _, f := range h.Findings {
		out = append(out, f.CheckID+" "+f.Title)
	}
	return out
}

func secCount(f *collect.Facts) int {
	if f.Updates == nil || f.Updates.Err != "" || f.Updates.Manager == "" {
		return -1
	}
	if f.Updates.Manager == "apk" {
		return len(f.Updates.Pending)
	}
	return len(f.Updates.Security)
}

// diffSets returns the unique items only in after (added) and only in
// before (removed), each sorted.
func diffSets(before, after []string) (added, removed []string) {
	b, a := map[string]bool{}, map[string]bool{}
	for _, x := range before {
		b[x] = true
	}
	for _, x := range after {
		a[x] = true
	}
	for x := range a {
		if !b[x] {
			added = append(added, x)
		}
	}
	for x := range b {
		if !a[x] {
			removed = append(removed, x)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func suids(f *collect.Facts) []string {
	var out []string
	for _, s := range f.SUID {
		out = append(out, s.Path)
	}
	return out
}

func onOff(b bool) string {
	if b {
		return "active"
	}
	return "inactive"
}

func orNone(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}
