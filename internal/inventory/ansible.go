package inventory

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// An Ansible inventory, as an INI file or as the JSON that
// `ansible-inventory -i <any inventory> --list` prints (which covers YAML
// and dynamic inventories). Hosts keep their inventory names in reports;
// ansible_host, ansible_port and ansible_user (or the older ansible_ssh_*
// names) say where and as whom to connect.
type ansibleInventory struct {
	order    []string                     // hosts in the order they first appear
	vars     map[string]map[string]string // host -> its own variables
	groups   map[string]*ansibleGroup
	notGroup map[string]bool // names used as hosts, to catch a mistyped -group
}

type ansibleGroup struct {
	hosts    []string
	children []string
	vars     map[string]string
}

func newAnsible() *ansibleInventory {
	return &ansibleInventory{vars: map[string]map[string]string{}, groups: map[string]*ansibleGroup{}, notGroup: map[string]bool{}}
}

func (a *ansibleInventory) group(name string) *ansibleGroup {
	g := a.groups[name]
	if g == nil {
		g = &ansibleGroup{vars: map[string]string{}}
		a.groups[name] = g
	}
	return g
}

func (a *ansibleInventory) addHost(group, host string, vars map[string]string) {
	if _, ok := a.vars[host]; !ok {
		a.order = append(a.order, host)
		a.vars[host] = map[string]string{}
	}
	for k, v := range vars {
		a.vars[host][k] = v
	}
	a.notGroup[host] = true
	g := a.group(group)
	for _, h := range g.hosts {
		if h == host {
			return
		}
	}
	g.hosts = append(g.hosts, host)
}

// sectionHeader matches [group] and [group:kind] (parseAnsibleINI checks
// the kind), but not a bracketed IPv6 address like [2001:db8::1].
var sectionHeader = regexp.MustCompile(`^\[[A-Za-z0-9_.-]+(:[A-Za-z]+)?\]$`)

// isAnsibleINI reports whether an inventory file looks like Ansible's INI
// format: a [group] header, or host variables such as ansible_host=.
func isAnsibleINI(lines []string) bool {
	for _, l := range lines {
		if sectionHeader.MatchString(l) || strings.Contains(l, "ansible_") {
			return true
		}
	}
	return false
}

// parseAnsibleINI reads an Ansible INI inventory. lines are trimmed, with
// comments removed; nums are their line numbers.
func parseAnsibleINI(lines []string, nums []int) (*ansibleInventory, error) {
	a := newAnsible()
	group, kind := "ungrouped", "hosts"
	for i, l := range lines {
		if sectionHeader.MatchString(l) {
			group, kind, _ = strings.Cut(l[1:len(l)-1], ":")
			if kind == "" {
				kind = "hosts"
			}
			if kind != "hosts" && kind != "vars" && kind != "children" {
				return nil, fmt.Errorf("line %d: unknown section [%s:%s]", nums[i], group, kind)
			}
			a.group(group)
			continue
		}
		switch kind {
		case "vars":
			k, v, ok := strings.Cut(l, "=")
			if !ok {
				return nil, fmt.Errorf("line %d: want key=value in [%s:vars]", nums[i], group)
			}
			a.group(group).vars[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
		case "children":
			a.group(l)
			a.group(group).children = append(a.group(group).children, l)
		default:
			fields := strings.Fields(l)
			vars := map[string]string{}
			for _, f := range fields[1:] {
				k, v, ok := strings.Cut(f, "=")
				if !ok {
					return nil, fmt.Errorf("line %d: want key=value after the host name, got %q", nums[i], f)
				}
				vars[k] = unquote(v)
			}
			names, err := expandRange(fields[0])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", nums[i], err)
			}
			for _, n := range names {
				a.addHost(group, n, vars)
			}
		}
	}
	return a, nil
}

// parseAnsibleJSON reads `ansible-inventory --list` output, whose hostvars
// already include group variables.
func parseAnsibleJSON(data []byte) (*ansibleInventory, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("not ansible-inventory --list JSON: %w", err)
	}
	var meta struct {
		HostVars map[string]map[string]any `json:"hostvars"`
	}
	if m, ok := raw["_meta"]; ok {
		if err := json.Unmarshal(m, &meta); err != nil {
			return nil, fmt.Errorf("_meta: %w", err)
		}
	}
	a := newAnsible()
	names := make([]string, 0, len(raw))
	for n := range raw {
		if n != "_meta" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		var g struct {
			Hosts    []string       `json:"hosts"`
			Children []string       `json:"children"`
			Vars     map[string]any `json:"vars"`
		}
		if err := json.Unmarshal(raw[name], &g); err != nil {
			return nil, fmt.Errorf("group %s: %w", name, err)
		}
		grp := a.group(name)
		grp.children = append(grp.children, g.Children...)
		for k, v := range g.Vars {
			grp.vars[k] = fmt.Sprint(v)
		}
		for _, h := range g.Hosts {
			vars := map[string]string{}
			for k, v := range meta.HostVars[h] {
				vars[k] = fmt.Sprint(v)
			}
			a.addHost(name, h, vars)
		}
	}
	return a, nil
}

// hosts returns the hosts in the given groups (all when none are given),
// with group variables applied from the outermost group in. Hosts with
// ansible_connection=local are left out and named in skipped.
func (a *ansibleInventory) hosts(groups []string, defaultUser string) (out []Host, skipped []string, err error) {
	want := map[string]bool{}
	if len(groups) > 0 {
		for _, g := range groups {
			if _, ok := a.groups[g]; !ok && g != "all" {
				hint := ""
				if a.notGroup[g] {
					hint = " (it is a host; give hosts as arguments)"
				}
				return nil, nil, fmt.Errorf("no group %q in the inventory%s", g, hint)
			}
			a.collect(g, want, map[string]bool{})
		}
	}
	for _, name := range a.order {
		if len(groups) > 0 && !want[name] && !contains(groups, "all") {
			continue
		}
		vars := a.effectiveVars(name)
		if vars["ansible_connection"] == "local" {
			skipped = append(skipped, name)
			continue
		}
		h := Host{Name: name, Addr: name, User: defaultUser}
		if p, _, ok := strings.Cut(name, ":"); ok && !strings.Contains(p, "[") && strings.Count(name, ":") == 1 {
			h.Addr = p // INI allows host:port
			port, err := strconv.Atoi(name[len(p)+1:])
			if err != nil || port < 1 || port > 65535 {
				return nil, nil, fmt.Errorf("host %s: invalid port", name)
			}
			h.Port = port
		}
		if v := first(vars, "ansible_host", "ansible_ssh_host"); v != "" {
			h.Addr = v
		}
		if v := first(vars, "ansible_port", "ansible_ssh_port"); v != "" {
			port, err := strconv.Atoi(v)
			if err != nil || port < 1 || port > 65535 {
				return nil, nil, fmt.Errorf("host %s: invalid ansible_port %q", name, v)
			}
			h.Port = port
		}
		if v := first(vars, "ansible_user", "ansible_ssh_user"); v != "" {
			h.User = v
		}
		out = append(out, h)
	}
	return out, skipped, nil
}

// collect adds the hosts of a group and of its children to set.
func (a *ansibleInventory) collect(group string, set, seen map[string]bool) {
	if seen[group] {
		return
	}
	seen[group] = true
	if group == "all" {
		for _, h := range a.order {
			set[h] = true
		}
		return
	}
	g := a.groups[group]
	if g == nil {
		return
	}
	for _, h := range g.hosts {
		set[h] = true
	}
	for _, c := range g.children {
		a.collect(c, set, seen)
	}
}

// effectiveVars applies variables as Ansible does: [all:vars] first, then
// the host's groups from parent to child, then the host's own variables.
func (a *ansibleInventory) effectiveVars(host string) map[string]string {
	vars := map[string]string{}
	for k, v := range a.group("all").vars {
		vars[k] = v
	}
	depth := map[string]int{}
	var walk func(name string, d int, seen map[string]bool)
	walk = func(name string, d int, seen map[string]bool) {
		if seen[name] {
			return
		}
		seen[name] = true
		if d > depth[name] {
			depth[name] = d
		}
		if a.groups[name] == nil {
			return
		}
		for _, c := range a.groups[name].children {
			walk(c, d+1, seen)
		}
	}
	names := make([]string, 0, len(a.groups))
	for n := range a.groups {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		walk(n, 1, map[string]bool{})
	}
	var mine []string
	for _, n := range names {
		for _, h := range a.groups[n].hosts {
			if h == host && n != "all" {
				mine = append(mine, n)
			}
		}
	}
	// Groups the host is in, plus their ancestors, parents first.
	in := map[string]bool{}
	for _, n := range mine {
		in[n] = true
	}
	for changed := true; changed; {
		changed = false
		for _, n := range names {
			if in[n] {
				continue
			}
			for _, c := range a.groups[n].children {
				if in[c] && n != "all" {
					in[n], changed = true, true
					break
				}
			}
		}
	}
	var chain []string
	for n := range in {
		chain = append(chain, n)
	}
	sort.Slice(chain, func(i, j int) bool {
		if depth[chain[i]] != depth[chain[j]] {
			return depth[chain[i]] < depth[chain[j]]
		}
		return chain[i] < chain[j]
	})
	for _, n := range chain {
		for k, v := range a.groups[n].vars {
			vars[k] = v
		}
	}
	for k, v := range a.vars[host] {
		vars[k] = v
	}
	return vars
}

// expandRange expands Ansible host ranges: web[01:03] gives web01, web02,
// web03; db-[a:c] gives db-a, db-b, db-c; [1:9:2] steps by 2.
func expandRange(name string) ([]string, error) {
	open := strings.Index(name, "[")
	if open < 0 {
		return []string{name}, nil
	}
	end := strings.Index(name[open:], "]")
	if end < 0 {
		return nil, fmt.Errorf("unclosed range in %q", name)
	}
	end += open
	parts := strings.Split(name[open+1:end], ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("bad range in %q: want [start:end] or [start:end:step]", name)
	}
	step := 1
	if len(parts) == 3 {
		s, err := strconv.Atoi(parts[2])
		if err != nil || s < 1 {
			return nil, fmt.Errorf("bad step in %q", name)
		}
		step = s
	}
	prefix, suffix := name[:open], name[end+1:]
	var items []string
	if lo, err1 := strconv.Atoi(parts[0]); err1 == nil {
		hi, err2 := strconv.Atoi(parts[1])
		if err2 != nil || hi < lo || hi-lo > 10000 {
			return nil, fmt.Errorf("bad range in %q", name)
		}
		width := 0
		if len(parts[0]) > 1 && parts[0][0] == '0' {
			width = len(parts[0])
		}
		for i := lo; i <= hi; i += step {
			items = append(items, fmt.Sprintf("%0*d", width, i))
		}
	} else if len(parts[0]) == 1 && len(parts[1]) == 1 && parts[0][0] <= parts[1][0] {
		for c := parts[0][0]; c <= parts[1][0]; c += byte(step) {
			items = append(items, string(c))
			if int(c)+step > 255 {
				break
			}
		}
	} else {
		return nil, fmt.Errorf("bad range in %q", name)
	}
	var out []string
	for _, it := range items {
		rest, err := expandRange(suffix) // a name may hold several ranges
		if err != nil {
			return nil, err
		}
		for _, r := range rest {
			out = append(out, prefix+it+r)
		}
	}
	return out, nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func first(vars map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := vars[k]; v != "" {
			return v
		}
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
