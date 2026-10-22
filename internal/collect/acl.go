package collect

import (
	"strconv"
	"strings"
)

// ACL is a file's extended access ACL: the owning group's permissions and
// those of named users and groups, each already limited by the mask (read
// 4, write 2, execute 1). The owner's and others' permissions are the
// mode's, as without an ACL.
type ACL struct {
	Group  uint32         // the owning group (group::)
	Users  map[int]uint32 // named users (user:UID:)
	Groups map[int]uint32 // named groups (group:GID:)
}

// aclsFn defines acls, which prints the extended access ACL entries of the
// paths on its input (one per line) as "acl|path|entry", with numeric IDs,
// for the files that have any. Without getfacl (busybox, minimal installs)
// it prints nothing: ACLs are read where the tool to set them is.
const aclsFn = `acls() {
  command -v getfacl >/dev/null 2>&1 || { cat >/dev/null; return; }
  tr '\n' '\0' | xargs -0 getfacl -s -p -n 2>/dev/null | awk '
    /^# file: / { f = substr($0, 9); next }
    /^#/ || /^default:/ || NF == 0 { next }
    { sub(/[ \t]*#.*$/, ""); print "acl|" f "|" $0 }'
}
`

// parseACLs turns "acl|path|entry" lines into ACLs by path. getfacl
// writes special characters in paths as \ooo.
func parseACLs(lines []string) map[string]*ACL {
	type raw struct {
		acl  ACL
		mask uint32
	}
	byPath := map[string]*raw{}
	for _, line := range lines {
		rest := strings.TrimPrefix(line, "acl|")
		i := strings.LastIndexByte(rest, '|')
		if i < 0 {
			continue
		}
		p, entry := unescapeOctal(rest[:i]), strings.TrimSpace(rest[i+1:])
		f := strings.Split(entry, ":")
		if len(f) != 3 || len(f[2]) != 3 {
			continue
		}
		var perm uint32
		for k, c := range f[2] {
			if c != '-' {
				perm |= 4 >> k
			}
		}
		r := byPath[p]
		if r == nil {
			r = &raw{mask: 7, acl: ACL{Users: map[int]uint32{}, Groups: map[int]uint32{}}}
			byPath[p] = r
		}
		id, err := strconv.Atoi(f[1])
		switch {
		case f[0] == "mask":
			r.mask = perm
		case f[0] == "group" && f[1] == "":
			r.acl.Group = perm
		case f[0] == "user" && err == nil:
			r.acl.Users[id] = perm
		case f[0] == "group" && err == nil:
			r.acl.Groups[id] = perm
		}
	}
	out := map[string]*ACL{}
	for p, r := range byPath {
		a := r.acl
		a.Group &= r.mask
		for id := range a.Users {
			a.Users[id] &= r.mask
		}
		for id := range a.Groups {
			a.Groups[id] &= r.mask
		}
		out[p] = &a
	}
	return out
}

// Ways an account gets access to a file, from access.
const (
	viaOwner    = "owner"
	viaACLUser  = "acl user"  // a named user entry
	viaGroup    = "group"     // the owning group, by mode or ACL
	viaACLGroup = "acl group" // a named group entry
	viaOther    = "other"
)

// access reports how an account with uid, in the groups gids, gets every
// permission in want on e, or "" when it does not, as the kernel decides:
// the owner gets the owner's bits; then a named user entry decides; then if
// the owning group or a named group matches, access is granted when one of
// them grants it and refused otherwise; then the others' bits decide. gid
// is the group that granted it. Root is not handled here.
func (e PathEntry) access(uid int, gids map[int]bool, want uint32) (via string, gid int) {
	allows := func(perm uint32) bool { return perm&want == want }
	if uid == e.UID {
		if allows(e.Mode >> 6 & 7) {
			return viaOwner, 0
		}
		return "", 0
	}
	if e.ACL != nil {
		if perm, ok := e.ACL.Users[uid]; ok {
			if allows(perm) {
				return viaACLUser, 0
			}
			return "", 0
		}
	}
	matched := false
	if gids[e.GID] {
		matched = true
		perm := e.Mode >> 3 & 7
		if e.ACL != nil {
			perm = e.ACL.Group
		}
		if allows(perm) {
			return viaGroup, e.GID
		}
	}
	if e.ACL != nil {
		best := -1
		for g, perm := range e.ACL.Groups {
			if gids[g] {
				matched = true
				if allows(perm) && (best < 0 || g < best) {
					best = g
				}
			}
		}
		if best >= 0 {
			return viaACLGroup, best
		}
	}
	if matched {
		return "", 0
	}
	if allows(e.Mode & 7) {
		return viaOther, 0
	}
	return "", 0
}

// account is an account other than root, with the IDs of every group it is
// in.
type account struct {
	name string
	uid  int
	gids map[int]bool
}

// accounts lists every account without UID 0, with its groups.
func (f *Facts) accounts() []account {
	gidOf := map[string]int{}
	for _, g := range f.Groups {
		gidOf[g.Name] = g.GID
	}
	var out []account
	for _, p := range f.Passwd {
		if p.UID == 0 {
			continue
		}
		a := account{name: p.Name, uid: p.UID, gids: map[int]bool{p.GID: true}}
		for _, g := range f.UserGroups(p.Name) {
			a.gids[gidOf[g]] = true
		}
		out = append(out, a)
	}
	return out
}
