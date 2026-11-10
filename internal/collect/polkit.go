package collect

import (
	"strings"
)

// Polkit is what decides who may do what without a password through
// polkit: its version (JavaScript rules need 0.106 or later; 0.105 only
// reads .pkla files), rules that answer YES, and .pkla sections.
type Polkit struct {
	Version string       `json:"version"`  // as the package or pkexec reports it, e.g. 0.105-33, 126-2; "" when polkit is not installed
	JSRules bool         `json:"js_rules"` // JavaScript rules count: polkit 0.106 and later
	PKLA    bool         `json:"pkla"`     // .pkla files count: polkit 0.105, or pkla-compat on later ones
	Rules   []PolkitRule `json:"rules,omitempty"`
	Grants  []PKLAGrant  `json:"grants,omitempty"`
}

// legacyPolkit reports whether a version is polkit 0.105 or older, which
// reads .pkla files and ignores JavaScript rules (Ubuntu 22.04: checked
// with pkexec, a YES rule did nothing there and a .pkla grant worked).
func legacyPolkit(v string) bool {
	rest, ok := strings.CutPrefix(v, "0.")
	if !ok {
		return false
	}
	n := 0
	for _, c := range rest {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n < 106
}

// PolkitRule is what nöbet reads from one polkit.addRule block of a
// JavaScript rules file: only identifiers, never the code.
type PolkitRule struct {
	File        string   `json:"file"`
	Yes         bool     `json:"yes"`                // it can return polkit.Result.YES
	Spawns      bool     `json:"spawns,omitempty"`   // it asks a program (pkla-compat): decided elsewhere
	ActionCheck bool     `json:"action_check"`       // it looks at action.id at all
	Actions     []string `json:"actions,omitempty"`  // action IDs it names
	Prefixes    []string `json:"prefixes,omitempty"` // action ID prefixes (indexOf(...) == 0, startsWith)
	Groups      []string `json:"groups,omitempty"`   // subject.isInGroup(...)
	Users       []string `json:"users,omitempty"`    // subject.user == ...
}

// PKLAGrant is a .pkla section that answers yes for some result.
type PKLAGrant struct {
	File       string   `json:"file"`
	Identities []string `json:"identities"` // unix-user:NAME, unix-group:NAME, * patterns
	Actions    []string `json:"actions"`    // glob patterns
}

// polkitScript prints polkit's version, whether .pkla files count, the
// identifiers of each addRule block that can say YES, and the .pkla
// sections' Identity, Action and Result lines. A host without polkit gets
// "none". Rule files only root (or polkitd) can read are read as root.
const polkitScript = `v=
command -v pkexec >/dev/null 2>&1 && v=$(pkexec --version 2>/dev/null | awk '{ print $NF; exit }')
[ -n "$v" ] || v=$(dpkg-query -W -f '${Version}\n' polkitd policykit-1 2>/dev/null | grep . | head -n 1)
[ -n "$v" ] || v=$(rpm -q --qf '%{VERSION}' polkit 2>/dev/null | grep -v 'not installed')
if [ -z "$v" ] && { [ -d /usr/share/polkit-1 ] || [ -d /etc/polkit-1 ]; }; then v=unknown; fi
if [ -z "$v" ]; then echo "none"; echo "@@end"; exit 0; fi
echo "version|$v"
[ -x /usr/bin/pkla-check-authorization ] && echo "pkla-compat"
for f in /etc/polkit-1/rules.d/*.rules /run/polkit-1/rules.d/*.rules /usr/local/share/polkit-1/rules.d/*.rules /usr/share/polkit-1/rules.d/*.rules; do
  [ -f "$f" ] || continue
  if [ ! -r "$f" ]; then echo "error|cannot read $f"; continue; fi
  awk -v F="$f" '{ l = $0; sub(/^[ \t]*\/\/.*$/, "", l); buf = buf " " l }
  function strs(s, re, kind,    t, q) {
    while (match(s, re)) {
      t = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
      if (match(t, /["\047][^"\047]*["\047]/)) { q = substr(t, RSTART + 1, RLENGTH - 2); out[kind] = out[kind] (out[kind] == "" ? "" : ",") q }
    }
  }
  END {
    while (match(buf, /\/\*([^*]|\*+[^*\/])*\*+\//)) buf = substr(buf, 1, RSTART - 1) substr(buf, RSTART + RLENGTH)
    while ((i = index(buf, "polkit.addRule(")) > 0) {
      buf = substr(buf, i + 15); depth = 1; j = 0; L = length(buf)
      while (j < L && depth > 0) { j++; c = substr(buf, j, 1); if (c == "(") depth++; else if (c == ")") depth-- }
      b = substr(buf, 1, j); buf = substr(buf, j + 1)
      delete out
      strs(b, "action\\.id[ \t]*===?[ \t]*[\"\047][^\"\047]*[\"\047]", "a")
      strs(b, "[\"\047][^\"\047]*[\"\047][ \t]*===?[ \t]*action\\.id", "a")
      strs(b, "action\\.id\\.(indexOf|startsWith)\\([ \t]*[\"\047][^\"\047]*[\"\047]", "p")
      strs(b, "isInGroup\\([ \t]*[\"\047][^\"\047]*[\"\047]", "g")
      strs(b, "subject\\.user[ \t]*===?[ \t]*[\"\047][^\"\047]*[\"\047]", "u")
      # An array of IDs tested with indexOf(action.id): its dotted strings.
      if (b ~ /indexOf\([ \t]*action\.id[ \t]*\)/) strs(b, "[\"\047][a-z][a-z0-9-]*(\\.[A-Za-z0-9_-]+)+[\"\047]", "a")
      print "rule|" F "|" (b ~ /polkit\.Result\.YES/ ? 1 : 0) "|" (b ~ /polkit\.spawn/ ? 1 : 0) "|" (b ~ /action\.id/ ? 1 : 0) "|" out["a"] "|" out["p"] "|" out["g"] "|" out["u"]
    }
  }' "$f"
done
for f in /etc/polkit-1/localauthority/*/*.pkla /var/lib/polkit-1/localauthority/*/*.pkla; do
  [ -f "$f" ] || continue
  if [ ! -r "$f" ]; then echo "error|cannot read $f"; continue; fi
  awk -v F="$f" '/^[ \t]*\[/ { print "pkla|" F "|section" }
    /^[ \t]*(Identity|Action|ResultAny|ResultInactive|ResultActive)[ \t]*=/ { l = $0; sub(/^[ \t]+/, "", l); k = l; sub(/[ \t]*=.*/, "", k); v = l; sub(/^[^=]*=[ \t]*/, "", v); print "pkla|" F "|" k "|" v }' "$f"
done
echo "@@end"
`

// parsePolkit reads polkitScript output. Without polkit it returns an
// empty Polkit; nil and the reason when a rules file could not be read or
// the listing stopped early.
func parsePolkit(s string) (*Polkit, string) {
	var p *Polkit
	type section struct {
		file      string
		ids, acts []string
		yes       bool
	}
	var cur *section
	flush := func() {
		if cur != nil && cur.yes {
			p.Grants = append(p.Grants, PKLAGrant{File: cur.file, Identities: cur.ids, Actions: cur.acts})
		}
		cur = nil
	}
	list := func(v, sep string) []string {
		var out []string
		for _, x := range strings.Split(v, sep) {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
		return out
	}
	for _, line := range lines(s) {
		f := strings.Split(line, "|")
		switch {
		case line == "@@end":
			if p == nil {
				return &Polkit{}, "" // not installed
			}
			flush()
			// An unknown version counts both kinds: fewer misses.
			legacy := legacyPolkit(p.Version)
			p.JSRules = !legacy
			p.PKLA = p.PKLA || legacy || p.Version == "unknown"
			return p, ""
		case line == "none":
		case f[0] == "version" && len(f) == 2:
			p = &Polkit{Version: f[1]}
		case p == nil:
		case line == "pkla-compat":
			p.PKLA = true
		case f[0] == "error" && len(f) == 2:
			return nil, f[1]
		case f[0] == "rule" && len(f) == 9:
			r := PolkitRule{File: f[1], Yes: f[2] == "1", Spawns: f[3] == "1", ActionCheck: f[4] == "1",
				Actions: list(f[5], ","), Prefixes: list(f[6], ","), Groups: list(f[7], ","), Users: list(f[8], ",")}
			if r.Yes && !r.Spawns {
				p.Rules = append(p.Rules, r)
			}
		case f[0] == "pkla" && len(f) == 3 && f[2] == "section":
			flush()
			cur = &section{file: f[1]}
		case f[0] == "pkla" && len(f) == 4 && cur != nil:
			switch f[2] {
			case "Identity":
				cur.ids = list(f[3], ";")
			case "Action":
				cur.acts = list(f[3], ";")
			default:
				cur.yes = cur.yes || strings.TrimSpace(f[3]) == "yes"
			}
		}
	}
	return nil, "the polkit listing stopped early"
}
