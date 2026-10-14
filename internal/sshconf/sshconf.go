// Package sshconf resolves hosts through ~/.ssh/config and
// /etc/ssh/ssh_config, the way ssh(1) does for the settings nobet uses:
// HostName, User, Port, IdentityFile and ProxyJump.
package sshconf

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"

	"github.com/olgacveysel/nobet/internal/inventory"
	"github.com/olgacveysel/nobet/internal/transport"
)

// Lookup reads ssh_config values for a host alias.
type Lookup interface {
	Get(alias, key string) string
	GetAll(alias, key string) []string
}

// System reads the user's and the system's ssh_config files.
type System struct{}

func (System) Get(alias, key string) string      { return ssh_config.Get(alias, key) }
func (System) GetAll(alias, key string) []string { return ssh_config.GetAll(alias, key) }

// Check reports whether the ssh_config files parse. When they don't, every
// lookup silently returns defaults, so callers should warn.
func Check() error {
	_, err := ssh_config.GetStrict("*", "HostName")
	return err
}

// File reads a single config file instead of the user's and the system's,
// like ssh -F.
type File struct{ cfg *ssh_config.Config }

// LoadFile parses the config file at path.
func LoadFile(path string) (File, error) {
	f, err := os.Open(path)
	if err != nil {
		return File{}, err
	}
	defer f.Close()
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return File{}, fmt.Errorf("%s: %w", path, err)
	}
	return File{cfg}, nil
}

func (f File) Get(alias, key string) string {
	v, _ := f.cfg.Get(alias, key)
	return v
}

func (f File) GetAll(alias, key string) []string {
	v, _ := f.cfg.GetAll(alias, key)
	return v
}

// None ignores ssh_config entirely.
type None struct{}

func (None) Get(string, string) string      { return "" }
func (None) GetAll(string, string) []string { return nil }

const maxDepth = 8

// Resolve turns an inventory host into a dialable target. Explicit values
// (user@host:port, -u) win over ssh_config, which wins over the defaults
// (your local username, port 22).
func Resolve(h inventory.Host, l Lookup) (transport.SSHTarget, error) {
	return resolve(h, l, 0)
}

func resolve(h inventory.Host, l Lookup, depth int) (transport.SSHTarget, error) {
	if depth > maxDepth {
		return transport.SSHTarget{}, fmt.Errorf("ProxyJump chain for %s is too deep (loop?)", h.Name)
	}
	alias := h.Addr

	host := l.Get(alias, "HostName")
	if host == "" {
		host = alias
	}
	host = strings.ReplaceAll(host, "%h", alias)

	user := h.User
	if user == "" {
		user = l.Get(alias, "User")
	}
	if user == "" {
		user = inventory.DefaultUser()
	}

	port := h.Port
	if port == 0 {
		if p, err := strconv.Atoi(l.Get(alias, "Port")); err == nil && p > 0 {
			port = p
		} else {
			port = 22
		}
	}

	t := transport.SSHTarget{Addr: net.JoinHostPort(host, strconv.Itoa(port)), User: user}
	for _, f := range l.GetAll(alias, "IdentityFile") {
		t.KeyFiles = append(t.KeyFiles, expand(f, alias, host, user))
	}

	jump := strings.TrimSpace(l.Get(alias, "ProxyJump"))
	if jump == "" || strings.EqualFold(jump, "none") {
		if pc := strings.TrimSpace(l.Get(alias, "ProxyCommand")); pc != "" && !strings.EqualFold(pc, "none") {
			return transport.SSHTarget{}, fmt.Errorf("%s uses ProxyCommand, which nobet does not support; use ProxyJump instead", alias)
		}
		return t, nil
	}

	// ProxyJump a,b means: connect to a, from a to b, from b to the host.
	var prev *transport.SSHTarget
	for _, hop := range strings.Split(jump, ",") {
		hh, err := inventory.Parse(strings.TrimSpace(hop), "")
		if err != nil {
			return transport.SSHTarget{}, fmt.Errorf("ProxyJump for %s: %w", alias, err)
		}
		ht, err := resolve(hh, l, depth+1)
		if err != nil {
			return transport.SSHTarget{}, err
		}
		if prev != nil {
			ht.Jump = prev
		}
		prev = &ht
	}
	t.Jump = prev
	return t, nil
}

// expand handles ~ and the common % tokens in IdentityFile paths.
func expand(path, alias, host, user string) string {
	home, _ := os.UserHomeDir()
	if path == "~" || strings.HasPrefix(path, "~/") {
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	return strings.NewReplacer(
		"%d", home,
		"%u", inventory.DefaultUser(),
		"%r", user,
		"%h", host,
		"%n", alias,
		"%%", "%",
	).Replace(path)
}
