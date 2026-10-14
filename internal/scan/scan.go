// Package scan holds what a scan of one host produces and evaluates
// collected facts into findings. Connecting to hosts lives in package
// fleet, so code that only reads results (the dashboard, reports) never
// links the SSH client.
package scan

import (
	"os"
	"sort"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/runner"
)

// Skip records a check that could not run on a host.
type Skip struct {
	CheckID string `json:"check_id"`
	Reason  string `json:"reason"`
}

// Suppressed is a finding covered by an allowlist rule.
type Suppressed struct {
	checks.Finding
	Reason string `json:"reason,omitempty"`
	Rule   string `json:"rule"` // file:line of the rule
}

// HostResult is everything nobet learned about one host.
type HostResult struct {
	Host       string           `json:"host"`
	Local      bool             `json:"local,omitempty"`
	OS         string           `json:"os,omitempty"`
	Error      string           `json:"error,omitempty"` // set when the host could not be scanned at all
	Privileged bool             `json:"privileged"`
	Findings   []checks.Finding `json:"findings"`
	Suppressed []Suppressed     `json:"suppressed,omitempty"`
	Skipped    []Skip           `json:"skipped,omitempty"`
	DurationMS int64            `json:"duration_ms"`

	// Facts are the raw collected data, used by rootmap and kept out of the
	// scan JSON to keep it readable.
	Facts *collect.Facts `json:"-"`
}

// LocalName is the name local scan results are reported under.
func LocalName() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "localhost"
	}
	return name
}

// Evaluate collects facts through r and runs every check against them.
func Evaluate(res *HostResult, r runner.Runner) {
	facts := collect.Collect(r)
	res.Facts = facts
	res.Privileged = facts.Privileged()
	res.OS = facts.OSRelease["PRETTY_NAME"]

	for _, c := range checks.All() {
		findings, skip := c.Run(facts)
		if skip != "" {
			res.Skipped = append(res.Skipped, Skip{CheckID: c.ID, Reason: skip})
			continue
		}
		res.Findings = append(res.Findings, findings...)
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity > res.Findings[j].Severity
	})
}
