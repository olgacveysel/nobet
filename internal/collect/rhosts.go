package collect

import (
	"strings"
)

// HostTrust is an entry of a file that lets sshd's host-based
// authentication log in from another host without a key or password:
// /etc/hosts.equiv, /etc/ssh/shosts.equiv, or an account's ~/.rhosts or
// ~/.shosts.
type HostTrust struct {
	File    string `json:"file"`
	Account string `json:"account,omitempty"` // whose ~/.rhosts or ~/.shosts; "" for the equiv files
	Host    string `json:"host"`              // a host, address or +@netgroup
	User    string `json:"user,omitempty"`    // the remote account it trusts, when named
}

// rhostsScript prints the entries of the host-based trust files: the
// system-wide ones, and every account's ~/.rhosts and ~/.shosts. Comments,
// negations and bare + wildcards (host or user) are left out: OpenSSH
// ignores wildcards (checked with OpenSSH 10 on Debian 13, where a + in
// hosts.equiv and "+ alice" in .rhosts let nobody in).
const rhostsScript = `entries() { # FILE ACCOUNT
  awk -v F="$1" -v A="$2" '{ sub(/#.*/, "") } NF > 0 && $1 != "+" && $2 != "+" && $1 !~ /^-/ { print "trust|" F "|" A "|" $1 "|" $2 }' "$1" 2>/dev/null
}
for f in /etc/hosts.equiv /etc/ssh/shosts.equiv; do
  [ -f "$f" ] && entries "$f" ""
done
awk -F: '$6 ~ /^\/./ { print $1 ":" $6 }' /etc/passwd | while IFS=: read -r u h; do
  for f in "$h/.rhosts" "$h/.shosts"; do
    [ -f "$f" ] && entries "$f" "$u"
  done
done
echo "@@end"
`

// parseRhosts reads rhostsScript output; nil when it stopped early.
func parseRhosts(s string) []HostTrust {
	out := []HostTrust{}
	for _, line := range lines(s) {
		if line == "@@end" {
			return out
		}
		p := strings.Split(line, "|")
		if len(p) == 5 && p[0] == "trust" {
			out = append(out, HostTrust{File: p[1], Account: p[2], Host: p[3], User: p[4]})
		}
	}
	return nil
}
