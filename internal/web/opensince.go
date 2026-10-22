package web

import (
	"fmt"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/store"
)

// Since when each current finding has been open, from the history. A
// finding is open from the first scan that reported it until a scan in
// which its check ran and did not report it: a scan that skipped the check
// (one without root, say) or failed says nothing either way. Findings are
// matched by check and text with numbers left out, so "3 pending updates"
// and "5 pending updates" are one finding. One whose text changed (a new
// package in the list) keeps the date of the one it replaced, when exactly
// one finding with that title went away and exactly one came.

// openKey identifies a finding across scans.
type openKey struct{ exact, title string }

func keyOf(f checks.Finding) openKey {
	t := f.CheckID + "\x00" + withoutNumbers(f.Title)
	return openKey{exact: t + "\x00" + withoutNumbers(f.Detail), title: t}
}

// withoutNumbers replaces each run of digits with #.
func withoutNumbers(s string) string {
	var b strings.Builder
	digits := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if !digits {
				b.WriteByte('#')
			}
			digits = true
			continue
		}
		digits = false
		b.WriteRune(r)
	}
	return b.String()
}

// carryOpen returns when each of h's findings opened, given the dates of
// the host's previous successful scan (nil for its first).
func carryOpen(prev map[openKey]time.Time, h store.HostSnapshot) map[openKey]time.Time {
	next := map[openKey]time.Time{}
	var fresh []openKey
	for _, f := range h.Findings {
		k := keyOf(f)
		if _, dup := next[k]; dup {
			continue
		}
		if t, ok := prev[k]; ok {
			next[k] = t
		} else {
			next[k] = h.Time
			fresh = append(fresh, k)
		}
	}
	skipped := map[string]bool{}
	for _, s := range h.Skipped {
		skipped[s.CheckID] = true
	}
	gone := map[string][]openKey{}
	for k, t := range prev {
		if _, still := next[k]; still {
			continue
		}
		if check, _, _ := strings.Cut(k.title, "\x00"); skipped[check] {
			next[k] = t // not checked this time: still open, as far as we know
			continue
		}
		gone[k.title] = append(gone[k.title], k)
	}
	came := map[string]int{}
	for _, k := range fresh {
		came[k.title]++
	}
	for _, k := range fresh {
		if g := gone[k.title]; len(g) == 1 && came[k.title] == 1 {
			next[k] = prev[g[0]]
		}
	}
	return next
}

// withOpen is a finding as the pages show it, with since when it has been
// open: "new in this scan", "open since 2026-09-03 (49 days)", or "or
// earlier" when that is the host's oldest scan in the history. Nothing
// for a host scanned only once.
func (ix *index) withOpen(host string, f checks.Finding, now time.Time) hostFinding {
	hf := hostFinding{Severity: f.Severity.String(), CheckID: f.CheckID, Title: f.Title, Detail: f.Detail, Fix: f.Fix}
	hist := ix.hist[host]
	opened, ok := ix.opened[host][keyOf(f)]
	if !ok || len(hist) < 2 {
		return hf
	}
	first, last := hist[0].Time, hist[len(hist)-1].Time
	days := int(now.Sub(opened).Hours() / 24)
	switch {
	case opened.Equal(last):
		hf.Open, hf.New = "new in this scan", true
	case opened.Equal(first):
		hf.Open = fmt.Sprintf("open since %s or earlier (%s)", opened.Format(time.DateOnly), dayCount(days))
	default:
		hf.Open = fmt.Sprintf("open since %s (%s)", opened.Format(time.DateOnly), dayCount(days))
	}
	return hf
}

func dayCount(n int) string {
	switch {
	case n < 1:
		return "today"
	case n == 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
