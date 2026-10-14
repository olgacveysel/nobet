// Package report renders scan results. The TUI will live alongside these
// plain renderers, which stay for scripting, CI and cron.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
)

// JSON writes results as indented JSON.
func JSON(w io.Writer, results []scan.HostResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// Text writes a human-readable report.
func Text(w io.Writer, results []scan.HostResult) {
	const indent = "               "

	for _, r := range results {
		header := r.Host
		if r.Local {
			header += " [local]"
		}
		if r.OS != "" {
			header += " (" + r.OS + ")"
		}
		fmt.Fprintf(w, "\n== %s ==\n", header)

		if r.Error != "" {
			fmt.Fprintf(w, "  ERROR: %s\n", r.Error)
			continue
		}
		if !r.Privileged {
			if r.Local {
				fmt.Fprintln(w, "  note: not running as root, so some checks were skipped (try: sudo nobet scan)")
			} else {
				fmt.Fprintln(w, "  note: no root or passwordless sudo, so some checks were skipped")
			}
		}
		if len(r.Findings) == 0 {
			fmt.Fprintln(w, "  no findings")
		}
		for _, f := range r.Findings {
			fmt.Fprintf(w, "  [%-8s] %s  %s\n", strings.ToUpper(f.Severity.String()), f.CheckID, f.Title)
			if f.Detail != "" {
				fmt.Fprintf(w, "%s%s\n", indent, f.Detail)
			}
			if f.Fix != "" {
				fmt.Fprintf(w, "%sfix: %s\n", indent, f.Fix)
			}
		}
		for _, s := range r.Skipped {
			fmt.Fprintf(w, "  [skipped ] %s  %s\n", s.CheckID, s.Reason)
		}
		if n := len(r.Suppressed); n > 0 {
			fmt.Fprintf(w, "  (%d finding(s) suppressed by the allowlist)\n", n)
		}
	}

	fmt.Fprintln(w)
	Summary(w, results)
}

// Summary writes a one-line overview of results.
func Summary(w io.Writer, results []scan.HostResult) {
	counts := map[checks.Severity]int{}
	unreachable, suppressed := 0, 0
	for _, r := range results {
		suppressed += len(r.Suppressed)
		if r.Error != "" {
			unreachable++
		}
		for _, f := range r.Findings {
			counts[f.Severity]++
		}
	}
	fmt.Fprintf(w, "%d host(s) scanned, %d unreachable | critical %d, high %d, medium %d, low %d, info %d",
		len(results), unreachable,
		counts[checks.Critical], counts[checks.High], counts[checks.Medium], counts[checks.Low], counts[checks.Info])
	if suppressed > 0 {
		fmt.Fprintf(w, " | %d allowlisted", suppressed)
	}
	fmt.Fprintln(w)
}
