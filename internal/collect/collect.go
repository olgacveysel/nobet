// Package collect gathers raw facts from a host. Collection is kept separate
// from evaluation so checks can be unit-tested against fake Facts without a
// real server. Every command here is read-only.
package collect

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/olgacveysel/nobet/internal/runner"
)

// RootEquivalentGroups grant root on the host to their members.
var RootEquivalentGroups = []string{"docker", "lxd", "incus"}

type PasswdEntry struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
	Home  string `json:"home"`
	Shell string `json:"shell"`
}

type GroupEntry struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

type Listener struct {
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
	Port  int    `json:"port"`
}

// SudoLine is one non-comment line from sudoers or sudoers.d.
type SudoLine struct {
	File string `json:"file"`
	Text string `json:"text"`
}

// SudoEntry is one rule from `sudo -l -U user`: what the user may run as whom.
type SudoEntry struct {
	RunAs    string   `json:"run_as"`
	NoPasswd bool     `json:"nopasswd"`
	NoExec   bool     `json:"noexec,omitempty"`
	Commands []string `json:"commands"`
}

// RootAll reports whether the rule lets the user run any command as root.
func (e SudoEntry) RootAll() bool {
	if !e.AsRoot() {
		return false
	}
	for _, c := range e.Commands {
		if c == "ALL" {
			return true
		}
	}
	return false
}

// AuthKey is one entry from a user's authorized_keys file.
type AuthKey struct {
	User        string   `json:"user"`
	File        string   `json:"file"`
	Type        string   `json:"type"`
	Fingerprint string   `json:"fingerprint"`
	Comment     string   `json:"comment,omitempty"`
	Options     []string `json:"options,omitempty"`
}

// Password states from /etc/shadow.
const (
	PasswordSet    = "set"
	PasswordEmpty  = "empty"  // no password at all: with pam_unix nullok, nothing to type
	PasswordLocked = "locked" // no usable password
)

// ShadowEntry is one account's password state. Hashes are never collected.
type ShadowEntry struct {
	User     string `json:"user"`
	Password string `json:"password"` // PasswordSet, PasswordEmpty or PasswordLocked
	Expired  bool   `json:"expired,omitempty"`
}

// SecurityUpdate is one pending security update or advisory.
type SecurityUpdate struct {
	Package  string `json:"package"`
	Severity string `json:"severity,omitempty"` // vendor severity when known: critical, important, moderate, low
}

// Updates describes pending package updates.
type Updates struct {
	Manager      string           `json:"manager"` // apt, dnf, dnf5, yum, zypper, apk, or "" if none found
	Security     []SecurityUpdate `json:"security"`
	Pending      []string         `json:"pending,omitempty"` // apk: every pending update, since apk does not label security fixes
	Total        int              `json:"total"`             // all pending updates; -1 if unknown
	ListsAgeDays int              `json:"lists_age_days"`    // days since the package indexes were refreshed; -1 if unknown
	Err          string           `json:"error,omitempty"`
}

// Reboot describes whether the host runs its newest installed kernel.
type Reboot struct {
	Running  string   `json:"running"`
	Latest   string   `json:"latest"`
	Flags    []string `json:"flags,omitempty"`    // e.g. /run/reboot-required
	Packages []string `json:"packages,omitempty"` // packages that asked for the reboot (Debian/Ubuntu)
}

// Firewall summarizes host firewall state.
type Firewall struct {
	UFW            string `json:"ufw,omitempty"`       // first line of `ufw status`
	Firewalld      string `json:"firewalld,omitempty"` // `firewall-cmd --state`
	NftChecked     bool   `json:"nft_checked"`
	NftInputRules  int    `json:"nft_input_rules"` // rules in chains hooked to input
	NftInputDrop   bool   `json:"nft_input_drop"`  // an input chain has policy drop
	IptChecked     bool   `json:"iptables_checked"`
	IptInputRules  int    `json:"iptables_input_rules"`
	IptInputPolicy string `json:"iptables_input_policy,omitempty"`
}

// Active reports whether any firewall filters incoming traffic.
func (fw *Firewall) Active() bool {
	return strings.HasPrefix(strings.ToLower(fw.UFW), "status: active") ||
		strings.TrimSpace(fw.Firewalld) == "running" ||
		fw.NftInputRules > 0 || fw.NftInputDrop ||
		fw.IptInputRules > 0 || fw.IptInputPolicy == "DROP" || fw.IptInputPolicy == "REJECT"
}

// Known reports whether any firewall tool could be inspected at all.
func (fw *Firewall) Known() bool {
	return fw.UFW != "" || fw.Firewalld != "" || fw.NftChecked || fw.IptChecked
}

// SUIDFile is a set-user-ID file.
type SUIDFile struct {
	Path  string `json:"path"`
	Owner string `json:"owner"` // pkg (owned by a package), none, or unknown (no dpkg/rpm)
}

// WritableEntry is a world-writable file or directory (without sticky bit).
type WritableEntry struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir"`
}

// Facts is everything collected from one host. A nil field means the data
// could not be collected; the reason is in Errors.
type Facts struct {
	IsRoot          bool                    // connected as root
	SudoOK          bool                    // passwordless sudo available
	OSRelease       map[string]string       // /etc/os-release
	ExtendedSupport []string                // Ubuntu Pro ESM services set up (esm-infra, esm-apps); nil if not Ubuntu or unreadable
	SSHD            map[string][]string     // effective config from `sshd -T`, keys lowercased; empty if sshd is not installed
	SSHDMatch       []SSHDContext           // where Match blocks change SSHD; nil if there are none or they could not be evaluated
	Sudoers         []SudoLine              // raw sudoers lines
	SudoRights      map[string][]SudoEntry  // per user, as resolved by sudo itself
	SudoDefaults    map[string]SudoDefaults // per user: the authentication Defaults sudo applies
	Passwd          []PasswdEntry
	Groups          []GroupEntry
	Shadow          []ShadowEntry // password states, root only
	AuthKeys        []AuthKey
	Listeners       []Listener
	Updates         *Updates
	Reboot          *Reboot
	AutoUpdates     map[string]string // how automatic updates are set up (autoUpdatesScript keys); nil if unknown
	Firewall        *Firewall
	SUID            []SUIDFile
	Writable        []WritableEntry
	// Files root runs or trusts that other accounts can change; nil if not
	// collected (root only). Only this result is kept in the scan history:
	// the listing it comes from is large.
	RootWritable []WritablePath
	RootJobs     []RootJob            `json:"-"` // what root runs or trusts
	Paths        map[string]PathEntry `json:"-"` // owner and mode of RootJobs' paths and the directories above them
	Links        map[string]string    `json:"-"` // symlinks among those paths, to their targets
	Interpreters map[string]string    `json:"-"` // scripts among those paths -> their #! interpreter
	Errors       map[string]string    // collector name -> why it failed
}

// Privileged reports whether root-only data could be collected.
func (f *Facts) Privileged() bool { return f.IsRoot || f.SudoOK }

// NoSSHD reports whether the host was found to have no sshd installed, as
// opposed to its config being unreadable.
func (f *Facts) NoSSHD() bool { return f.SSHD != nil && len(f.SSHD) == 0 }

// GroupMembers returns the users in a group, including users whose primary
// group it is. It returns nil if the group does not exist.
func (f *Facts) GroupMembers(name string) []string {
	gid := -1
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, g := range f.Groups {
		if g.Name == name {
			gid = g.GID
			for _, m := range g.Members {
				add(m)
			}
		}
	}
	if gid < 0 {
		return nil
	}
	for _, p := range f.Passwd {
		if p.GID == gid {
			add(p.Name)
		}
	}
	sort.Strings(out)
	return out
}

// Password returns user's password state and whether the account has
// expired. ok is false when shadow data is missing or lists no such user.
func (f *Facts) Password(user string) (state string, expired, ok bool) {
	for _, s := range f.Shadow {
		if s.User == user {
			return s.Password, s.Expired, true
		}
	}
	return "", false, false
}

// UserGroups returns the names of every group user belongs to, primary
// group included.
func (f *Facts) UserGroups(user string) []string {
	gid := -1
	for _, p := range f.Passwd {
		if p.Name == user {
			gid = p.GID
		}
	}
	var out []string
	for _, g := range f.Groups {
		member := g.GID == gid
		for _, m := range g.Members {
			member = member || m == user
		}
		if member {
			out = append(out, g.Name)
		}
	}
	return out
}

// Collect runs all collectors against r, which may be local or remote.
func Collect(r runner.Runner) *Facts {
	f := &Facts{Errors: map[string]string{}}

	if res, err := r.Run("id -u"); err == nil && strings.TrimSpace(res.Stdout) == "0" {
		f.IsRoot = true
	} else if res, err := r.Run("sudo -n true"); err == nil && res.ExitCode == 0 {
		f.SudoOK = true
	}

	run := func(name, cmd string) (string, bool) {
		res, err := r.Run(cmd)
		switch {
		case err != nil:
			f.Errors[name] = err.Error()
			return "", false
		case res.ExitCode != 0 && strings.TrimSpace(res.Stdout) == "":
			msg := strings.TrimSpace(res.Stderr)
			if msg == "" {
				msg = "exit status " + strconv.Itoa(res.ExitCode)
			}
			f.Errors[name] = msg
			return "", false
		}
		return res.Stdout, true
	}
	// Scripts are shipped base64-encoded so no quoting can break them, and
	// run as root through sudo when we have passwordless sudo.
	script := func(body string, asRoot bool) string {
		cmd := "echo " + base64.StdEncoding.EncodeToString([]byte(body)) + " | base64 -d | "
		if asRoot && f.SudoOK && !f.IsRoot {
			return cmd + "sudo -n sh"
		}
		return cmd + "sh"
	}

	if out, ok := run("os-release", "cat /etc/os-release"); ok {
		f.OSRelease = parseOSRelease(out)
	}
	if f.OSRelease["ID"] == "ubuntu" {
		if out, ok := run("esm", script(esmScript, false)); ok {
			if f.ExtendedSupport = parseESM(out); f.ExtendedSupport == nil {
				f.Errors["esm"] = "the ESM source check stopped early"
			}
		}
	}
	if out, ok := run("passwd", "cat /etc/passwd"); ok {
		f.Passwd = parsePasswd(out)
	}
	if out, ok := run("group", "cat /etc/group"); ok {
		f.Groups = parseGroup(out)
	}
	var matchLines []string
	if out, ok := run("sshd", script(sshdScript, true)); ok {
		var cfg string
		cfg, matchLines = splitSSHD(out)
		f.SSHD = parseSSHD(cfg)
	}
	if out, ok := run("listeners", script(listenersScript, false)); ok {
		f.Listeners = parseListeners(out)
		if f.Listeners == nil {
			f.Listeners = []Listener{}
		}
	}
	if out, ok := run("updates", script(updatesScript, true)); ok {
		f.Updates = parseUpdates(out)
	}
	if out, ok := run("reboot", script(rebootScript, false)); ok {
		f.Reboot = parseReboot(out)
	}
	if out, ok := run("autoupdates", script(autoUpdatesScript, false)); ok {
		if f.AutoUpdates = parseKeyValues(out); f.AutoUpdates == nil {
			f.Errors["autoupdates"] = "the listing stopped early"
		}
	}

	// Sudoers, firewall rules, file permissions across the system, other
	// users' keys and sudo rights are only fully readable as root; partial
	// data would look complete, so skip them entirely otherwise.
	if !f.Privileged() {
		for _, name := range []string{"sudoers", "shadow", "firewall", "files", "authkeys", "sudo-rights", "root-jobs"} {
			f.Errors[name] = "needs root or passwordless sudo"
		}
		return f
	}
	if out, ok := run("sudoers", script(sudoersScript, true)); ok {
		f.Sudoers = parseSudoers(out)
		if f.Sudoers == nil {
			f.Sudoers = []SudoLine{}
		}
	}
	if out, ok := run("shadow", script(shadowScript, true)); ok {
		f.Shadow = parseShadow(out)
	}
	if out, ok := run("firewall", script(firewallScript, true)); ok {
		f.Firewall = parseFirewall(out)
	}
	if out, ok := run("files", script(filesScript, true)); ok {
		f.SUID, f.Writable = parseFiles(out)
	}
	if out, ok := run("authkeys", script(authKeysScript, true)); ok {
		f.AuthKeys = parseAuthKeys(out)
		if f.AuthKeys == nil {
			f.AuthKeys = []AuthKey{}
		}
	}
	if out, ok := run("sudo-rights", script(sudoRightsScript, true)); ok {
		f.SudoRights, f.SudoDefaults = parseSudoRights(out)
	}
	f.collectRootPaths(func(name, body string) (string, bool) { return run(name, script(body, true)) })

	// Match blocks: ask sshd what applies to each root-capable account and
	// from each address range the blocks name.
	if len(f.SSHD) > 0 && len(matchLines) > 0 {
		addrs, from := probeAddrs(matchLines)
		fromAddr := map[string]string{}
		for i, a := range addrs {
			fromAddr[a] = from[i]
		}
		body := sshdMatchScript(probeUsers(f), addrs, sshdPort(f.SSHD))
		if out, ok := run("sshd-match", script(body, true)); ok {
			ctxs, err := parseSSHDMatch(out, f.SSHD, fromAddr)
			if err != nil {
				f.Errors["sshd-match"] = err.Error()
			} else {
				f.SSHDMatch = ctxs
			}
		}
	}
	return f
}

// collectRootPaths lists what root runs or trusts, then the owner and mode
// of every file involved and the directories above them, and keeps the
// ones other accounts can change in RootWritable. Needs SudoRights, Passwd
// and Groups first.
func (f *Facts) collectRootPaths(run func(name, body string) (string, bool)) {
	out, ok := run("root-jobs", rootJobsScript)
	if !ok {
		return
	}
	jobs := parseRootJobs(out)
	if jobs == nil {
		f.Errors["root-jobs"] = "the listing of what root runs stopped early"
		return
	}
	jobs = append(jobs, sudoJobs(f)...)
	jobs = append(jobs, securePathJob(f.Sudoers)...)
	paths, truncated := rootPaths(jobs)
	if out, ok = run("root-paths", pathsScript(paths)); !ok {
		return
	}
	entries, links, interps := parsePaths(out)
	if entries == nil {
		f.Errors["root-paths"] = "the file permission listing stopped early"
		return
	}
	f.RootJobs, f.Paths, f.Links, f.Interpreters = jobs, entries, links, interps
	f.RootWritable = f.writablePaths()
	if truncated {
		f.Errors["root-paths"] = fmt.Sprintf("only the first %d paths were checked", maxRootPaths)
	}
}

func parseOSRelease(s string) map[string]string {
	m := map[string]string{}
	for _, line := range lines(s) {
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = strings.Trim(v, `"'`)
		}
	}
	return m
}

// parseESM reads esmScript output. Without the closing "end" the list may
// be cut short, so it counts as not collected.
func parseESM(s string) []string {
	out := []string{}
	for _, line := range lines(s) {
		switch line {
		case "end":
			return out
		case "esm-infra", "esm-apps":
			out = append(out, line)
		}
	}
	return nil
}

func parsePasswd(s string) []PasswdEntry {
	var out []PasswdEntry
	for _, line := range lines(s) {
		p := strings.Split(line, ":")
		if len(p) < 7 {
			continue
		}
		uid, err1 := strconv.Atoi(p[2])
		gid, err2 := strconv.Atoi(p[3])
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, PasswdEntry{Name: p[0], UID: uid, GID: gid, Home: p[5], Shell: p[6]})
	}
	return out
}

func parseGroup(s string) []GroupEntry {
	var out []GroupEntry
	for _, line := range lines(s) {
		p := strings.Split(line, ":")
		if len(p) < 4 {
			continue
		}
		gid, err := strconv.Atoi(p[2])
		if err != nil {
			continue
		}
		g := GroupEntry{Name: p[0], GID: gid}
		for _, m := range strings.Split(p[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				g.Members = append(g.Members, m)
			}
		}
		out = append(out, g)
	}
	return out
}

func parseSSHD(s string) map[string][]string {
	m := map[string][]string{}
	for _, line := range lines(s) {
		k, v, _ := strings.Cut(line, " ")
		k = strings.ToLower(k)
		m[k] = append(m[k], strings.TrimSpace(v))
	}
	return m
}

func parseSudoers(s string) []SudoLine {
	var out []SudoLine
	for _, line := range lines(s) {
		file, text, ok := strings.Cut(line, ": ")
		if !ok {
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" || (strings.HasPrefix(text, "#") && !strings.HasPrefix(text, "#include")) {
			continue
		}
		out = append(out, SudoLine{File: file, Text: text})
	}
	return out
}

// parseShadow reads shadowScript output: "user state expired" per line.
func parseShadow(s string) []ShadowEntry {
	out := []ShadowEntry{}
	for _, line := range lines(s) {
		f := strings.Fields(line)
		if len(f) != 3 {
			continue
		}
		switch f[1] {
		case PasswordSet, PasswordEmpty, PasswordLocked:
			out = append(out, ShadowEntry{User: f[0], Password: f[1], Expired: f[2] == "1"})
		}
	}
	return out
}

// parseSS parses `ss -H -tuln`:
// tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
func parseSS(s string) []Listener {
	var out []Listener
	for _, line := range lines(s) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := fields[4]
		i := strings.LastIndex(local, ":")
		if i < 0 {
			continue
		}
		port, err := strconv.Atoi(local[i+1:])
		if err != nil {
			continue
		}
		addr := strings.Trim(local[:i], "[]")
		if z := strings.Index(addr, "%"); z >= 0 {
			addr = addr[:z] // drop interface zone: 127.0.0.53%lo
		}
		out = append(out, Listener{Proto: fields[0], Addr: addr, Port: port})
	}
	return out
}

// parseUpdates parses the key=value output of updatesScript.
func parseUpdates(s string) *Updates {
	u := &Updates{Total: -1, ListsAgeDays: -1}
	var now, refreshed int64
	rc := 0
	noCache := false
	seen := map[string]bool{}
	secIndex := map[string]int{}
	for _, line := range lines(s) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "manager":
			u.Manager = v
		case "now":
			now, _ = strconv.ParseInt(v, 10, 64)
		case "refreshed":
			if t, err := strconv.ParseInt(v, 10, 64); err == nil && t > refreshed {
				refreshed = t
			}
		case "rc":
			rc, _ = strconv.Atoi(v)
		case "nocache":
			noCache = true
		case "upd":
			if u.Total < 0 {
				u.Total = 0
			}
			u.Total++
			if u.Manager == "apk" {
				if name := rpmName(v); !seen["upd "+name] {
					seen["upd "+name] = true
					u.Pending = append(u.Pending, name)
				}
			}
		case "sec":
			sev, pkg, _ := strings.Cut(v, " ")
			pkg = strings.TrimSpace(pkg)
			if u.Manager == "dnf" || u.Manager == "dnf5" || u.Manager == "yum" {
				pkg = rpmName(pkg)
			}
			sev = strings.ToLower(strings.TrimSpace(sev))
			if i := strings.Index(sev, "/"); i >= 0 {
				sev = sev[:i] // dnf: "Important/Sec."
			}
			if sev == "-" {
				sev = ""
			}
			if pkg == "" {
				continue
			}
			if i, ok := secIndex[pkg]; ok {
				// Several advisories for one package: keep the worst.
				if severityRank[sev] > severityRank[u.Security[i].Severity] {
					u.Security[i].Severity = sev
				}
				continue
			}
			secIndex[pkg] = len(u.Security)
			u.Security = append(u.Security, SecurityUpdate{Package: pkg, Severity: sev})
		}
	}
	if (u.Manager == "apt" || u.Manager == "apk") && u.Total < 0 && rc == 0 {
		u.Total = 0
	}
	if now > 0 && refreshed > 0 {
		u.ListsAgeDays = int((now - refreshed) / 86400)
	}
	// zypper reports updates needed (100, 101) and reboot or restart
	// needed (102, 103) through its exit code. 106 means repositories were
	// skipped, so the list is incomplete.
	switch {
	case u.Manager == "zypper" && rc >= 100 && rc <= 103:
	case u.Manager == "zypper" && rc == 106:
		u.Err = "zypper skipped some repositories, so their package index cache is missing or broken"
	case rc != 0:
		u.Err = u.Manager + " query failed with exit status " + strconv.Itoa(rc)
	case noCache:
		u.Err = u.Manager + " package index cache is missing for some or all repositories"
	}
	return u
}

// severityRank orders vendor severities; unknown ones rank lowest.
var severityRank = map[string]int{"low": 1, "moderate": 2, "important": 3, "critical": 4}

// rpmName returns the package name from a name-[epoch:]version-release.arch
// string such as "vim-data-2:9.2.390-1.fc42.noarch". It also handles
// Alpine's name-version-rN.
func rpmName(nevra string) string {
	parts := strings.Split(nevra, "-")
	if len(parts) < 3 {
		return nevra
	}
	return strings.Join(parts[:len(parts)-2], "-")
}

// parseKeyValues reads key=value lines up to a closing "end"; without it
// the output may be cut short, and it returns nil.
func parseKeyValues(s string) map[string]string {
	m := map[string]string{}
	for _, line := range lines(s) {
		if line == "end" {
			return m
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			m[k] = v
		}
	}
	return nil
}

func parseReboot(s string) *Reboot {
	r := &Reboot{}
	seen := map[string]bool{}
	for _, line := range lines(s) {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "running":
			r.Running = v
		case "latest":
			r.Latest = v
		case "flag":
			r.Flags = append(r.Flags, v)
		case "pkg":
			if v != "" && !seen[v] {
				seen[v] = true
				r.Packages = append(r.Packages, v)
			}
		}
	}
	return r
}

// parseAuthKeys parses "user<TAB>file<TAB>authorized_keys line" records.
func parseAuthKeys(s string) []AuthKey {
	var out []AuthKey
	for _, line := range lines(s) {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(parts[2]))
		if err != nil {
			continue
		}
		out = append(out, AuthKey{
			User:        parts[0],
			File:        parts[1],
			Type:        pub.Type(),
			Fingerprint: ssh.FingerprintSHA256(pub),
			Comment:     comment,
			Options:     options,
		})
	}
	return out
}

// parseSudoRights parses `sudo -l -U user` output, with each user's section
// preceded by an "@@user name" marker line. Besides the rules it reads the
// Defaults sections to learn whose password sudo asks for.
func parseSudoRights(s string) (map[string][]SudoEntry, map[string]SudoDefaults) {
	m := map[string][]SudoEntry{}
	defs := map[string]SudoDefaults{}
	user, section := "", ""
	var lines []string
	endSection := func() {
		if user != "" && len(lines) > 0 {
			d := defs[user]
			switch section {
			case "defaults":
				d.Flags = readFlags(splitTopLevel(strings.Join(lines, ",")))
			case "scoped":
				d.Scoped = parseScoped(strings.Join(lines, " "))
			}
			if d.Flags != nil || d.Scoped != nil {
				defs[user] = d
			}
		}
		lines, section = nil, ""
	}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		// Defaults lists are indented and end at a blank line or the next
		// heading.
		if (section == "defaults" || section == "scoped") && (line == "" || !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t")) {
			endSection()
		}
		switch {
		case strings.HasPrefix(line, "@@user "):
			user, section = strings.TrimSpace(line[len("@@user "):]), ""
		case strings.HasPrefix(line, "Matching Defaults entries for "):
			section = "defaults"
		case strings.HasPrefix(line, "Runas and Command-specific defaults"):
			section = "scoped"
		case strings.Contains(line, "may run the following commands"):
			section = "rules"
		case section == "defaults" || section == "scoped":
			lines = append(lines, line)
		case section == "rules" && user != "" && strings.HasPrefix(line, "("):
			if e, ok := parseSudoEntry(line); ok {
				m[user] = append(m[user], e)
			}
		}
	}
	endSection()
	return m, defs
}

// parseSudoEntry parses one rule such as "(ALL : ALL) NOPASSWD: ALL".
func parseSudoEntry(line string) (SudoEntry, bool) {
	end := strings.Index(line, ")")
	if !strings.HasPrefix(line, "(") || end < 0 {
		return SudoEntry{}, false
	}
	e := SudoEntry{RunAs: strings.TrimSpace(line[1:end])}
	rest := strings.TrimSpace(line[end+1:])
	// Leading tags look like NOPASSWD:, SETENV:, NOEXEC:, ...
	for {
		tag, after, ok := strings.Cut(rest, ":")
		if !ok || tag == "" || strings.ToUpper(tag) != tag || strings.ContainsAny(tag, " /") {
			break
		}
		switch tag {
		case "NOPASSWD":
			e.NoPasswd = true
		case "PASSWD":
			e.NoPasswd = false
		case "NOEXEC":
			e.NoExec = true
		case "EXEC":
			e.NoExec = false
		}
		rest = strings.TrimSpace(after)
	}
	for _, c := range strings.Split(rest, ",") {
		if c = strings.TrimSpace(c); c != "" {
			e.Commands = append(e.Commands, c)
		}
	}
	return e, len(e.Commands) > 0
}

// parseFirewall reads firewallScript output.
func parseFirewall(s string) *Firewall {
	fw := &Firewall{}
	section := ""
	var nft []string
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "@@nft":
			section, fw.NftChecked = "nft", true
		case line == "@@iptables":
			section, fw.IptChecked = "ipt", true
		case line == "@@end":
			section = ""
		case section == "nft":
			nft = append(nft, line)
		case section == "ipt":
			if strings.HasPrefix(line, "-P INPUT ") {
				fw.IptInputPolicy = strings.TrimSpace(strings.TrimPrefix(line, "-P INPUT "))
			} else if strings.HasPrefix(line, "-A INPUT ") {
				fw.IptInputRules++
			}
		case strings.HasPrefix(line, "ufw="):
			fw.UFW = strings.TrimPrefix(line, "ufw=")
		case strings.HasPrefix(line, "firewalld="):
			fw.Firewalld = strings.TrimPrefix(line, "firewalld=")
		}
	}
	fw.NftInputRules, fw.NftInputDrop = nftInput(nft)
	return fw
}

// nftInput counts rules in nftables chains hooked to input and reports
// whether any of them drops by default.
func nftInput(lines []string) (rules int, drop bool) {
	inChain, isInput := false, false
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "chain "):
			inChain, isInput = true, false
		case inChain && l == "}":
			inChain = false
		case inChain && strings.HasPrefix(l, "type ") && strings.Contains(l, "hook input"):
			isInput = true
			if strings.Contains(l, "policy drop") {
				drop = true
			}
		case inChain && isInput && l != "" && !strings.HasPrefix(l, "#"):
			rules++
		}
	}
	return rules, drop
}

// parseFiles reads filesScript output.
func parseFiles(s string) ([]SUIDFile, []WritableEntry) {
	suid, ww := []SUIDFile{}, []WritableEntry{}
	for _, line := range lines(s) {
		switch {
		case strings.HasPrefix(line, "suid="):
			owner, path, ok := strings.Cut(strings.TrimPrefix(line, "suid="), " ")
			if ok && path != "" {
				suid = append(suid, SUIDFile{Path: path, Owner: owner})
			}
		case strings.HasPrefix(line, "ww="):
			kind, path, ok := strings.Cut(strings.TrimPrefix(line, "ww="), " ")
			if ok && path != "" {
				ww = append(ww, WritableEntry{Path: path, Dir: kind == "d"})
			}
		}
	}
	return suid, ww
}

func lines(s string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(s))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			out = append(out, l)
		}
	}
	return out
}
