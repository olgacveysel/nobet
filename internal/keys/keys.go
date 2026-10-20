// Package keys maps SSH keys to the people (or systems) they belong to, so
// the root access map can name them, point out keys nobody claims, and
// answer "where can this person become root?" when someone leaves.
//
// The file has one key per line: the owner, then the key as a SHA256
// fingerprint or as a public key line from authorized_keys:
//
//	alice  SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU   # laptop
//	alice  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMq... alice@desktop
//	ci     SHA256:HRmMEMU9cyejr7STBxyzzOI4cfmC7Xkho7aTuOfNdNA   # deploy pipeline
//
// An owner can have any number of keys; a key has one owner. Everything
// after a # that starts a word is a note.
package keys

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// fingerprint is a SHA256 key fingerprint as ssh-keygen -lf prints it.
var fingerprint = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// Owners is a loaded keys file. The zero value knows no keys.
type Owners struct {
	Path string // "" when no file was loaded
	byFP map[string]string
}

// DefaultPath is ~/.config/nobet/keys (or the platform equivalent).
func DefaultPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "nobet", "keys")
}

// Load reads a keys file. A missing file is an error only when required is
// true, so the default location can be optional.
func Load(p string, required bool) (*Owners, error) {
	if p == "" {
		return &Owners{}, nil
	}
	f, err := os.Open(p)
	if err != nil {
		if !required && errors.Is(err, fs.ErrNotExist) {
			return &Owners{}, nil
		}
		return nil, err
	}
	defer f.Close()
	m, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &Owners{Path: p, byFP: m}, nil
}

// Parse reads key lines from r into fingerprint -> owner.
func Parse(r io.Reader) (map[string]string, error) {
	m := map[string]string{}
	lineOf := map[string]int{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // RSA public keys are long
	for n := 1; sc.Scan(); n++ {
		line := stripNote(sc.Text())
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 2 {
			return nil, fmt.Errorf("line %d: want <owner> <SHA256 fingerprint or public key>", n)
		}
		owner := fields[0]
		var fp string
		if strings.HasPrefix(fields[1], "SHA256:") {
			if !fingerprint.MatchString(fields[1]) || len(fields) > 2 {
				return nil, fmt.Errorf("line %d: %q is not a SHA256 fingerprint as ssh-keygen -lf prints it", n, fields[1])
			}
			fp = fields[1]
		} else {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(fields[1:], " ")))
			if err != nil {
				return nil, fmt.Errorf("line %d: not a fingerprint or a public key: %v", n, err)
			}
			fp = ssh.FingerprintSHA256(pub)
		}
		if prev, ok := m[fp]; ok && prev != owner {
			return nil, fmt.Errorf("line %d: key %s already belongs to %s (line %d)", n, fp, prev, lineOf[fp])
		}
		m[fp], lineOf[fp] = owner, n
	}
	return m, sc.Err()
}

// stripNote removes a # note that starts the line or follows whitespace.
func stripNote(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
	}
	return s
}

// Owner returns who a key belongs to, or "".
func (o *Owners) Owner(fingerprint string) string {
	if o == nil {
		return ""
	}
	return o.byFP[fingerprint]
}

// Loaded reports whether a keys file was read.
func (o *Owners) Loaded() bool { return o != nil && o.Path != "" }

// Has reports whether anyone by that name owns a key in the file.
func (o *Owners) Has(owner string) bool {
	if o == nil {
		return false
	}
	for _, v := range o.byFP {
		if v == owner {
			return true
		}
	}
	return false
}
