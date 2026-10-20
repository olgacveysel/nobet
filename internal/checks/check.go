// Package checks evaluates collected facts and produces findings.
//
// To add a check: define a Check in the file for its area (ssh.go,
// access.go, network.go, ...) and add it to All.
package checks

import (
	"fmt"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText makes severities appear as names in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText reads severity names back, for saved scan history.
func (s *Severity) UnmarshalText(b []byte) error {
	v, ok := ParseSeverity(string(b))
	if !ok {
		return fmt.Errorf("unknown severity %q", b)
	}
	*s = v
	return nil
}

// ParseSeverity parses a severity name, case-insensitively.
func ParseSeverity(v string) (Severity, bool) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), true
		}
	}
	return 0, false
}

// Finding is one problem found on a host.
type Finding struct {
	CheckID  string   `json:"check_id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"`
	Fix      string   `json:"fix,omitempty"`
}

// Check evaluates facts. Run returns the findings (none means pass), or a
// non-empty skip reason when the facts it needs could not be collected.
type Check struct {
	ID    string
	Title string
	Run   func(f *collect.Facts) (findings []Finding, skip string)
}

// unavailable explains why root-only data is missing: no privilege, or the
// collector's own error when it failed despite privilege (a timeout, say).
func unavailable(f *collect.Facts, collector, what string) string {
	if !f.Privileged() {
		return what + " unavailable (needs root or passwordless sudo)"
	}
	if e := f.Errors[collector]; e != "" {
		return what + " unavailable: " + e
	}
	return what + " unavailable"
}

// All returns every built-in check in report order.
func All() []Check {
	return []Check{
		sshRootLogin,
		sshPasswordAuth,
		sshEmptyPasswords,
		sshX11Forwarding,
		uidZeroAccounts,
		sudoNoPassword,
		sudoShellEscape,
		rootGroupMembers,
		emptyPasswords,
		exposedListeners,
		hostFirewall,
		pendingSecurityUpdates,
		rebootRequired,
		staleUpdateLists,
		osSupport,
		suidFiles,
		worldWritable,
		rootWritable,
	}
}
