package collect

import (
	"strings"
)

// PAMLine is one auth line of a PAM service file, or an include of another
// file. Arguments are only kept for the modules whose arguments decide what
// they do here (pam_wheel, pam_succeed_if, pam_faillock): others can hold
// secrets (pam_exec, RADIUS and LDAP modules), so they stay on the host.
type PAMLine struct {
	Type    string   `json:"type"`    // auth, or @include (Debian: every type of the named file)
	Control string   `json:"control"` // required, requisite, sufficient, optional, include, substack or [value=action ...]
	Module  string   `json:"module"`  // module file name without directory (pam_unix.so), or the included file
	Args    []string `json:"args,omitempty"`
}

// pamArgModules are the modules whose arguments leave the host.
var pamArgModules = map[string]bool{"pam_wheel.so": true, "pam_succeed_if.so": true, "pam_faillock.so": true}

// pamScript prints every file in /etc/pam.d as "@@file NAME" followed by
// its lines without comments, continuation lines joined. Which of them
// matter is decided by the parser; only "@@end" ends the listing.
const pamScript = `[ -d /etc/pam.d ] || { echo "@@none"; echo "@@end"; exit 0; }
for f in /etc/pam.d/*; do
  [ -f "$f" ] || continue
  if [ ! -r "$f" ]; then echo "@@unreadable $f"; continue; fi
  echo "@@file ${f##*/}"
  awk '{ sub(/#.*/, "") } /\\$/ { sub(/\\$/, ""); held = held $0 " "; next } { print held $0; held = "" }' "$f" |
    awk 'NF > 0 && ($1 ~ /^-?auth$/ || $1 == "@include") {
      t = $1; sub(/^-/, "", t)
      if (t == "@include") { print "pam|@include||" $2 "|"; next }
      ctl = $2; i = 3
      if (ctl ~ /^\[/) { while (ctl !~ /\]$/ && i <= NF) { ctl = ctl " " $i; i++ } }
      mod = $i; n = split(mod, parts, "/"); mod = parts[n]
      args = ""
      if (mod == "pam_wheel.so" || mod == "pam_succeed_if.so" || mod == "pam_faillock.so") for (j = i + 1; j <= NF; j++) args = args " " $j
      print "pam|auth|" ctl "|" mod "|" substr(args, 2)
    }'
done
echo "@@end"
`

// parsePAM reads pamScript output: auth lines by service file name. It
// returns nil and the reason when the listing is incomplete or a file
// could not be read. A host without /etc/pam.d gets an empty map.
func parsePAM(s string) (map[string][]PAMLine, string) {
	out := map[string][]PAMLine{}
	file := ""
	for _, line := range lines(s) {
		switch {
		case line == "@@end":
			return out, ""
		case line == "@@none":
		case strings.HasPrefix(line, "@@unreadable "):
			return nil, "cannot read " + strings.TrimPrefix(line, "@@unreadable ")
		case strings.HasPrefix(line, "@@file "):
			file = strings.TrimPrefix(line, "@@file ")
			out[file] = []PAMLine{}
		case strings.HasPrefix(line, "pam|") && file != "":
			p := strings.SplitN(line, "|", 5)
			if len(p) != 5 {
				continue
			}
			l := PAMLine{Type: p[1], Control: p[2], Module: p[3]}
			if pamArgModules[l.Module] && p[4] != "" {
				l.Args = strings.Fields(p[4])
			}
			out[file] = append(out[file], l)
		}
	}
	return nil, "the PAM listing stopped early"
}
