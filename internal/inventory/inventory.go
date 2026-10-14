// Package inventory parses the list of hosts to scan.
package inventory

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Host is one SSH target as written by the user. Addr may be an alias from
// ~/.ssh/config; Port and User are zero/empty when not given, so the SSH
// config (or the defaults) can fill them in.
type Host struct {
	Name string // as written by the user, used in reports
	Addr string // hostname, IP address or ssh_config alias
	Port int    // 0 if not given
	User string // "" if not given
}

// Target returns the host:port string to dial, defaulting to port 22.
func (h Host) Target() string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(h.Addr, strconv.Itoa(port))
}

// Load reads an inventory file with one [user@]host[:port] per line.
// Blank lines and anything after # are ignored.
func Load(path, defaultUser string) ([]Host, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []Host
	sc := bufio.NewScanner(f)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		h, err := Parse(line, defaultUser)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		hosts = append(hosts, h)
	}
	return hosts, sc.Err()
}

// Parse parses a single [user@]host[:port] target. IPv6 addresses with a
// port must be bracketed: [2001:db8::1]:2222. defaultUser may be empty.
func Parse(s, defaultUser string) (Host, error) {
	h := Host{Name: s, User: defaultUser}
	if at := strings.LastIndex(s, "@"); at >= 0 {
		h.User, s = s[:at], s[at+1:]
	}
	if host, port, err := net.SplitHostPort(s); err == nil {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return Host{}, fmt.Errorf("invalid port in %q", h.Name)
		}
		h.Addr, h.Port = host, p
	} else {
		h.Addr = strings.Trim(s, "[]")
	}
	if h.Addr == "" {
		return Host{}, fmt.Errorf("missing host in %q", h.Name)
	}
	return h, nil
}

// DefaultUser returns the local username, without a Windows domain prefix.
func DefaultUser() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	name := u.Username
	if i := strings.LastIndex(name, `\`); i >= 0 {
		name = name[i+1:]
	}
	return name
}
