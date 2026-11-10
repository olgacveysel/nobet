package collect

import (
	"strconv"
	"strings"
)

// FileCap is a file with capabilities (security.capability), as getcap
// prints them.
type FileCap struct {
	Path   string `json:"path"`
	Owner  string `json:"owner"`            // pkg (owned by a package), none, or unknown (no dpkg/rpm)
	Caps   string `json:"caps"`             // getcap's text: "cap_setuid=ep", "= cap_net_raw+p", "=ep"
	RootID int    `json:"rootid,omitempty"` // a namespaced capability's root uid; 0 counts on the host
}

// Permitted reports whether the file's capability text puts name (such as
// "cap_setuid") in the permitted set: a program can raise a permitted
// capability itself (an interpreter with capset), so effective does not
// matter. Clauses follow cap_from_text(3): no names or "all" means every
// capability, "=" sets exactly the flags given, "+" adds, "-" removes.
func (c FileCap) Permitted(name string) bool {
	all, set := false, map[string]bool{}
	for _, clause := range strings.Fields(strings.ToLower(c.Caps)) {
		i := strings.IndexAny(clause, "=+-")
		if i < 0 {
			continue
		}
		var names []string
		if n := clause[:i]; n != "" && n != "all" {
			names = strings.Split(n, ",")
		}
		ops := clause[i:]
		for ops != "" {
			op := ops[0]
			j := strings.IndexAny(ops[1:], "=+-")
			flags := ops[1:]
			if j >= 0 {
				flags, ops = ops[1:j+1], ops[j+1:]
			} else {
				ops = ""
			}
			p := strings.Contains(flags, "p")
			if op != '=' && !p {
				continue
			}
			v := op != '-'
			if op == '=' {
				v = p
			}
			if names == nil {
				all, set = v, map[string]bool{}
				continue
			}
			for _, n := range names {
				set[n] = v
			}
		}
	}
	if v, ok := set[name]; ok {
		return v
	}
	return all
}

// parseFileCaps reads fileCapsScript output: nil when getcap is missing or
// the listing stopped early (missing is an error too: nothing could be
// checked).
func parseFileCaps(s string) ([]FileCap, string) {
	out := []FileCap{}
	for _, line := range lines(s) {
		switch {
		case line == "nogetcap":
			return nil, "getcap is not installed (libcap2-bin, libcap or libcap-progs)"
		case line == "@@end":
			return out, ""
		case strings.HasPrefix(line, "cap="):
			p := strings.SplitN(strings.TrimPrefix(line, "cap="), "|", 4)
			if len(p) != 4 || p[3] == "" {
				continue
			}
			r, _ := strconv.Atoi(p[1])
			out = append(out, FileCap{Path: p[3], Owner: p[0], Caps: p[2], RootID: r})
		}
	}
	return nil, "the file capability listing stopped early"
}
