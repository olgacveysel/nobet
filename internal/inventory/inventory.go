// Package inventory parses the list of hosts to scan.
package inventory

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/user"
	"regexp"
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

// Load reads an inventory file: one [user@]host[:port] per line (blank
// lines and anything after # are ignored), an Ansible INI inventory, or the
// JSON of `ansible-inventory --list`. groups picks Ansible groups (all
// hosts when empty). skipped names Ansible hosts that are not reached over
// SSH (ansible_connection=local).
func Load(path, defaultUser string, groups []string) (hosts []Host, skipped []string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, "{") {
		a, err := parseAnsibleJSON(data)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return wrap(path)(a.hosts(groups, defaultUser))
	}

	var lines []string
	var nums []int
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, ";") {
			line = "" // Ansible INI comment
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			lines, nums = append(lines, line), append(nums, lineNo)
		}
	}
	if len(lines) > 0 && (lines[0] == "---" || yamlKey.MatchString(lines[0])) {
		return nil, nil, fmt.Errorf("%s: YAML inventories are not read directly; use the JSON that `ansible-inventory -i %s --list` prints", path, path)
	}
	if isAnsibleINI(lines) {
		a, err := parseAnsibleINI(lines, nums)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		return wrap(path)(a.hosts(groups, defaultUser))
	}
	if len(groups) > 0 {
		return nil, nil, fmt.Errorf("%s: -group needs an Ansible inventory; this file is a plain host list", path)
	}
	for i, line := range lines {
		h, err := Parse(line, defaultUser)
		if err != nil {
			return nil, nil, fmt.Errorf("%s:%d: %w", path, nums[i], err)
		}
		hosts = append(hosts, h)
	}
	return hosts, nil, nil
}

// yamlKey matches a YAML mapping key on its own line, like "all:".
var yamlKey = regexp.MustCompile(`^[A-Za-z0-9_-]+:$`)

// wrap prefixes an error with the file name.
func wrap(path string) func([]Host, []string, error) ([]Host, []string, error) {
	return func(h []Host, s []string, err error) ([]Host, []string, error) {
		if err != nil {
			err = fmt.Errorf("%s: %w", path, err)
		}
		return h, s, err
	}
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
