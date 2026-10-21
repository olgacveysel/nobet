package collect

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// PrivateKey is a private key file that an account other than root and its
// owner can read. Key contents never leave the host: the collector reads a
// key's first line (its PEM header) there and takes the public
// fingerprint from the .pub file or from the public part an OpenSSH-format
// key carries in clear.
type PrivateKey struct {
	Path        string   `json:"path"`
	Kind        string   `json:"kind"`                  // ssh (an account's key), host (sshd's host key) or tls
	Format      string   `json:"format"`                // from the PEM header: OPENSSH, RSA, EC, ENCRYPTED, or "" for PKCS#8
	Fingerprint string   `json:"fingerprint,omitempty"` // SSH-256 fingerprint, when it could be read without the passphrase
	Owner       string   `json:"owner"`                 // the account that owns the file
	Everyone    bool     `json:"everyone,omitempty"`    // every account can read it
	Group       string   `json:"group,omitempty"`       // the group whose members can read it
	Readers     []string `json:"readers,omitempty"`     // accounts besides root and the owner that can read it
}

// privateKeysScript finds private keys in every account's ~/.ssh, sshd's
// host keys and the usual TLS key directories, and prints the owner and
// mode of each and of every directory above it.
const privateKeysScript = `cands() {
  awk -F: '$6 ~ /^\/./ { print $6 }' /etc/passwd | sort -u | while IFS= read -r h; do
    for f in "$h"/.ssh/*; do echo "ssh|$f"; done
  done
  for f in /etc/ssh/ssh_host_*_key; do echo "host|$f"; done
  for f in /etc/ssl/private/* /etc/pki/tls/private/* /etc/letsencrypt/archive/*/privkey*.pem; do echo "tls|$f"; done
}
# Key lines go to stdout (4); each key's path and the directories above it
# go through 3 to stat.
{ cands | head -n 2000 | while IFS='|' read -r kind f; do
  case $f in *.pub | */known_hosts* | */authorized_keys* | */config | *'*'*) continue ;; esac
  [ -f "$f" ] && [ ! -L "$f" ] || continue
  first=$(head -c 100 "$f" 2>/dev/null | head -n 1)
  case $first in '-----BEGIN '*'PRIVATE KEY-----'*) ;; *) continue ;; esac
  format=${first#-----BEGIN }
  format=${format%%PRIVATE KEY-----*}
  format=${format% }
  fp=
  if [ -f "$f.pub" ]; then
    fp=$(ssh-keygen -l -f "$f.pub" </dev/null 2>/dev/null | awk '{ print $2 }')
  elif [ "$kind" != tls ] && [ "$format" != ENCRYPTED ]; then
    fp=$(ssh-keygen -l -f "$f" </dev/null 2>/dev/null | awk '{ print $2 }')
  fi
  echo "key|$kind|$f|$format|$fp"
  q=$f
  while [ -n "$q" ]; do echo "$q" >&3; q=${q%/*}; done
done 3>&1 1>&4 | { echo /; sort -u; } | tr '\n' '\0' | xargs -0 stat -c 'stat|%u|%g|%a|%F|%n' 2>/dev/null; } 4>&1
echo "@@end"
`

// privateKey is a key file found by privateKeysScript, before deciding
// who can read it.
type privateKey struct {
	kind, path, format, fp string
}

// parsePrivateKeys reads privateKeysScript output and keeps the keys that
// someone besides root and their owner can read. It returns nil when the
// output is incomplete.
func (f *Facts) parsePrivateKeys(s string) []PrivateKey {
	var found []privateKey
	for _, line := range strings.Split(s, "\n") {
		if p := strings.Split(strings.TrimRight(line, "\r"), "|"); len(p) == 5 && p[0] == "key" {
			fp := p[4]
			if !strings.HasPrefix(fp, "SHA256:") {
				fp = ""
			}
			found = append(found, privateKey{p[1], p[2], p[3], fp})
		}
	}
	entries, _, _, _ := parsePaths(s)
	if entries == nil {
		return nil
	}
	out := []PrivateKey{}
	for _, k := range found {
		if pk, ok := f.keyReaders(k, entries); ok {
			out = append(out, pk)
		}
	}
	return out
}

// keyReaders works out who besides root and the file's owner can read a
// key: everyone, when the file is readable by others and every directory
// above it can be entered by others; the members of its group, when it is
// group-readable and each directory above it lets them through. Groups
// that only system services are meant to be in (ssl-cert, ssh_keys) count
// only for keys of accounts.
func (f *Facts) keyReaders(k privateKey, entries map[string]PathEntry) (PrivateKey, bool) {
	st, ok := entries[k.path]
	if !ok || st.Type != "file" {
		return PrivateKey{}, false
	}
	names, groups := map[int]string{}, map[int]string{}
	for _, e := range f.Passwd {
		if _, dup := names[e.UID]; !dup {
			names[e.UID] = e.Name
		}
	}
	for _, g := range f.Groups {
		groups[g.GID] = g.Name
	}
	name := func(uid int) string {
		if n, ok := names[uid]; ok {
			return n
		}
		return "uid " + strconv.Itoa(uid)
	}
	pk := PrivateKey{Path: k.path, Kind: k.kind, Format: k.format, Fingerprint: k.fp, Owner: name(st.UID)}

	othersThrough, groupThrough := true, true
	for _, d := range chain(k.path)[1:] {
		de, ok := entries[d]
		if !ok || de.Type != "dir" {
			return PrivateKey{}, false
		}
		if de.Mode&0o001 == 0 {
			othersThrough = false
			if de.Mode&0o010 == 0 || de.GID != st.GID {
				groupThrough = false
			}
		}
	}
	pk.Everyone = othersThrough && st.Mode&0o004 != 0
	if !pk.Everyone && groupThrough && st.Mode&0o040 != 0 {
		g := groups[st.GID]
		service := g == "ssl-cert" || g == "ssh_keys" || g == "root"
		if g != "" && !(service && k.kind != "ssh") {
			for _, m := range f.GroupMembers(g) {
				if m != "root" && m != pk.Owner {
					pk.Readers = append(pk.Readers, m)
				}
			}
			if len(pk.Readers) > 0 {
				pk.Group = g
				sort.Strings(pk.Readers)
			}
		}
	}
	// An account's key in another account's ~/.ssh: the file's owner can
	// read a key that is not theirs.
	if k.kind == "ssh" && st.UID != 0 {
		home := path.Dir(path.Dir(k.path))
		for _, e := range f.Passwd {
			if e.Home == home && e.UID != st.UID && !contains(pk.Readers, pk.Owner) {
				pk.Readers = append(pk.Readers, pk.Owner)
				break
			}
		}
	}
	return pk, pk.Everyone || len(pk.Readers) > 0
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
