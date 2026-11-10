package collect

import (
	"sort"
	"strconv"
	"strings"
)

// RootDoor is a way to root other than sudo: the control socket of a
// daemon that runs as root and does what its clients ask (start a
// privileged container, mount the host's disk into a VM), or a raw disk.
// Whoever can open it is root on the host.
type RootDoor struct {
	Path     string   `json:"path"`
	Kind     string   `json:"kind"`               // docker, podman, containerd, cri-o, incus, lxd, libvirt, systemd or disk
	Everyone bool     `json:"everyone,omitempty"` // every account can open it
	Accounts []string `json:"accounts,omitempty"` // accounts besides root that can (disk: read and write)
	Readers  []string `json:"readers,omitempty"`  // disk: accounts that can only read it
	ReadAll  bool     `json:"read_all,omitempty"` // disk: every account can read it
	Group    string   `json:"group,omitempty"`    // the owning group, when it lets some of them in
	ACL      []string `json:"acl,omitempty"`      // the accounts an ACL entry lets in
	Polkit   bool     `json:"polkit,omitempty"`   // libvirt: the socket is open to all and polkit decides
	More     int      `json:"more,omitempty"`     // disk: further devices with the same access
}

// doorSockets are the root daemons' control sockets, by kind. Incus's
// unix.socket.user (the incus group) is left out: incus-user gives each
// account a restricted project, without privileged containers or host
// paths (checked with Incus 6.0). libvirt's read-only sockets are left
// out too.
var doorSockets = [][2]string{
	{"/run/docker.sock", "docker"}, {"/var/run/docker.sock", "docker"},
	{"/run/podman/podman.sock", "podman"},
	{"/run/containerd/containerd.sock", "containerd"}, {"/run/k3s/containerd/containerd.sock", "containerd"},
	{"/run/crio/crio.sock", "cri-o"},
	{"/var/lib/incus/unix.socket", "incus"},
	{"/var/snap/lxd/common/lxd/unix.socket", "lxd"}, {"/var/lib/lxd/unix.socket", "lxd"},
	{"/run/libvirt/libvirt-sock", "libvirt"}, {"/run/libvirt/virtqemud-sock", "libvirt"},
	{"/run/libvirt/virtlxcd-sock", "libvirt"}, {"/run/libvirt/virtxend-sock", "libvirt"},
	{"/run/systemd/private", "systemd"},
}

// doorsScript prints the sockets of doorSockets that exist (by their real
// path: /var/run is usually a link to /run) and the block devices in /dev,
// then the owner, mode and ACL entries of each and of every directory
// above it.
func doorsScript() string {
	var socks []string
	for _, s := range doorSockets {
		socks = append(socks, s[1]+"="+s[0])
	}
	return aclsFn + `{ { for s in ` + strings.Join(socks, " ") + `; do
  p=${s#*=}
  [ -S "$p" ] || continue
  r=$(readlink -f "$p" 2>/dev/null) || r=$p
  echo "door|${s%%=*}|${r:-$p}"
done
for d in /dev/*; do [ -b "$d" ] && [ ! -L "$d" ] && echo "door|disk|$d"; done; } | sort -u | while IFS='|' read -r tag kind p; do
  echo "$tag|$kind|$p"
  q=$p
  while [ -n "$q" ]; do echo "$q" >&3; q=${q%/*}; done
done 3>&1 1>&4 | {
  all=$({ echo /; sort -u; })
  printf '%s\n' "$all" | tr '\n' '\0' | xargs -0 stat -c 'stat|%u|%g|%a|%F|%n' 2>/dev/null
  printf '%s\n' "$all" | acls
}; } 4>&1
echo "@@end"
`
}

// parseDoors reads doorsScript output and works out who can open each
// door; nil when the output is incomplete.
func (f *Facts) parseDoors(s string) []RootDoor {
	entries, _, _, _ := parsePaths(s)
	if entries == nil {
		return nil
	}
	groups := map[int]string{}
	for _, g := range f.Groups {
		groups[g.GID] = g.Name
	}
	accts := f.accounts()
	out := []RootDoor{}
	disks := map[string]int{} // access signature -> index in out
	seen := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		p := strings.SplitN(strings.TrimRight(line, "\r"), "|", 3)
		if len(p) != 3 || p[0] != "door" || seen[p[2]] {
			continue
		}
		seen[p[2]] = true
		d := RootDoor{Path: p[2], Kind: p[1]}
		e, ok := entries[d.Path]
		if !ok {
			continue
		}
		dirs := chain(d.Path)[1:]
		want := uint32(2) // connecting to a socket takes write permission
		if d.Kind == "disk" {
			want = 6
		}
		var vias []string
		d.Everyone, d.Accounts, vias = whoCan(e, dirs, entries, accts, want)
		if d.Kind == "disk" && !d.Everyone {
			var readers []string
			var all bool
			all, readers, _ = whoCan(e, dirs, entries, accts, 4)
			d.ReadAll = all
			for _, r := range readers {
				if !contains(d.Accounts, r) {
					d.Readers = append(d.Readers, r)
				}
			}
		}
		if d.Kind == "libvirt" && d.Everyone {
			// libvirtd and virtqemud open their sockets to all and ask
			// polkit (org.libvirt.unix.manage), whose rule from the
			// packages lets the libvirt group in.
			d.Everyone, d.Polkit, d.Group, d.Accounts, vias = false, true, "libvirt", nil, nil
			for _, m := range f.GroupMembers("libvirt") {
				if f.uidOf(m) != 0 {
					d.Accounts = append(d.Accounts, m)
				}
			}
		}
		for i, v := range vias {
			switch v {
			case viaGroup:
				if d.Group = groups[e.GID]; d.Group == "" {
					d.Group = "gid " + strconv.Itoa(e.GID)
				}
			case viaACLUser, viaACLGroup:
				d.ACL = append(d.ACL, d.Accounts[i])
			}
		}
		if !d.Everyone && !d.ReadAll && len(d.Accounts)+len(d.Readers) == 0 {
			continue
		}
		if d.Kind == "disk" {
			// Partitions and loop devices mostly share one access list.
			sig := strconv.FormatBool(d.Everyone) + strconv.FormatBool(d.ReadAll) + "|" + strings.Join(d.Accounts, ",") + "|" + strings.Join(d.Readers, ",") + "|" + d.Group + "|" + strings.Join(d.ACL, ",")
			if i, ok := disks[sig]; ok {
				out[i].More++
				if pseudoDisk(out[i].Path) && !pseudoDisk(d.Path) {
					out[i].Path = d.Path // name a real disk, not /dev/loop0
				}
				continue
			}
			disks[sig] = len(out)
		}
		out = append(out, d)
	}
	return out
}

// whoCan reports whether every account can get the permissions in want on
// the file e (others' bits, and every directory in dirs enterable by
// others), and otherwise which accounts can, with how each got in.
func whoCan(e PathEntry, dirs []string, entries map[string]PathEntry, accts []account, want uint32) (everyone bool, names, vias []string) {
	everyone = e.Mode&want == want
	for _, d := range dirs {
		de, ok := entries[d]
		if !ok || de.Type != "dir" {
			return false, nil, nil
		}
		everyone = everyone && de.Mode&1 != 0
	}
	if everyone {
		return true, nil, nil
	}
	type got struct{ name, via string }
	var found []got
	for _, a := range accts {
		via, _ := e.access(a.uid, a.gids, want)
		if via == "" {
			continue
		}
		through := true
		for _, d := range dirs {
			if v, _ := entries[d].access(a.uid, a.gids, 1); v == "" {
				through = false
				break
			}
		}
		if through {
			found = append(found, got{a.name, via})
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].name < found[j].name })
	for _, g := range found {
		names = append(names, g.name)
		vias = append(vias, g.via)
	}
	return false, names, vias
}

// pseudoDisk reports whether a block device is a loop, RAM or zram device
// rather than a disk.
func pseudoDisk(p string) bool {
	for _, s := range []string{"/dev/loop", "/dev/ram", "/dev/zram"} {
		if strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// uidOf is an account's UID, or -1 when there is none.
func (f *Facts) uidOf(name string) int {
	for _, p := range f.Passwd {
		if p.Name == name {
			return p.UID
		}
	}
	return -1
}

// RootDoorGroups are the groups whose members were taken to be root before
// nobet looked at the sockets themselves; old scans without RootDoors still
// use them. The incus group is not one: incus-user restricts it.
var RootDoorGroups = []string{"docker", "lxd", "incus-admin"}

// RootDoorRoutes maps each account besides root that can open a root door
// to how, such as "Docker (docker group)" or "raw disks (disk group)". A
// door every account can open is listed under "*".
func (f *Facts) RootDoorRoutes() map[string][]string {
	out := map[string][]string{}
	add := func(acct, how string) {
		if !contains(out[acct], how) {
			out[acct] = append(out[acct], how)
		}
	}
	if f.RootDoors == nil {
		for _, g := range RootDoorGroups {
			for _, u := range f.GroupMembers(g) {
				if f.uidOf(u) != 0 {
					add(u, g+" group")
				}
			}
		}
		return out
	}
	for _, d := range f.RootDoors {
		if d.Everyone {
			add("*", DoorName(d.Kind)+" ("+d.Path+" is open to all)")
		}
		for _, a := range d.Accounts {
			add(a, d.How(a))
		}
	}
	return out
}

// How says how account a gets through d: "Docker (docker group)",
// "Docker (ACL on /run/docker.sock)", "libvirt (libvirt group, polkit)".
func (d RootDoor) How(a string) string {
	how := DoorName(d.Kind)
	switch {
	case contains(d.ACL, a):
		return how + " (ACL on " + d.Path + ")"
	case d.Polkit:
		return how + " (" + d.Group + " group, polkit)"
	case d.Group != "":
		return how + " (" + d.Group + " group)"
	}
	return how + " (" + d.Path + ")"
}

// DoorName is how a kind of RootDoor is called in findings.
func DoorName(kind string) string {
	switch kind {
	case "docker":
		return "Docker"
	case "cri-o":
		return "CRI-O"
	case "incus":
		return "Incus"
	case "lxd":
		return "LXD"
	case "systemd":
		return "systemd's private socket"
	case "disk":
		return "raw disks"
	}
	return kind
}
