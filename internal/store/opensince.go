package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
)

// Openings knows since when each host's current findings have been open.
// A finding is open from the first scan that reported it until a scan in
// which its check ran and did not report it: a scan that skipped the check
// (one without root, say) or failed says nothing either way. Findings are
// matched by check and text with numbers left out, so "3 pending updates"
// and "5 pending updates" are one finding. One whose text changed (a new
// package in the list) keeps the date of the one it replaced, when exactly
// one finding with that title went away and exactly one came.
type Openings struct {
	open        map[string]map[openKey]time.Time
	first, last map[string]time.Time
	scans       map[string]int
}

// NewOpenings returns an empty tracker; feed it scans with Add.
func NewOpenings() *Openings {
	return &Openings{open: map[string]map[openKey]time.Time{}, first: map[string]time.Time{},
		last: map[string]time.Time{}, scans: map[string]int{}}
}

// OpenSince reads the history in dir into a tracker.
func OpenSince(dir string) (*Openings, error) {
	o := NewOpenings()
	err := Walk(dir, func(s Snapshot) error {
		for _, h := range s.Hosts {
			o.Add(h)
		}
		return nil
	})
	return o, err
}

// Add takes a host's next scan, in time order. Failed scans change
// nothing.
func (o *Openings) Add(h HostSnapshot) {
	if h.Error != "" || h.Facts == nil {
		return
	}
	if o.scans[h.Host] == 0 {
		o.first[h.Host] = h.Time
	}
	o.scans[h.Host]++
	o.last[h.Host] = h.Time
	o.open[h.Host] = carryOpen(o.open[h.Host], h)
}

// Text says since when a current finding of host has been open, as of now:
// "new in this scan" (isNew), "open since 2026-09-03 (49 days)", or with
// "or earlier" when that is the host's oldest scan kept. It is "" for a
// host scanned only once, and for a finding it does not know.
func (o *Openings) Text(host string, f checks.Finding, now time.Time) (text string, isNew bool) {
	if o == nil || o.scans[host] < 2 {
		return "", false
	}
	opened, ok := o.Opened(host, f)
	if !ok {
		return "", false
	}
	days := int(now.Sub(opened).Hours() / 24)
	switch {
	case o.IsNew(host, f):
		return "new in this scan", true
	case opened.Equal(o.first[host]):
		return fmt.Sprintf("open since %s or earlier (%s)", opened.Format(time.DateOnly), dayCount(days)), false
	}
	return fmt.Sprintf("open since %s (%s)", opened.Format(time.DateOnly), dayCount(days)), false
}

// Opened returns when a current finding of host opened: the host's oldest
// kept scan if it was there already, so the finding may be older still.
func (o *Openings) Opened(host string, f checks.Finding) (time.Time, bool) {
	if o == nil {
		return time.Time{}, false
	}
	t, ok := o.open[host][keyOf(f)]
	return t, ok
}

// IsNew reports whether a current finding of host was first reported in
// its newest scan, after earlier scans that did not have it.
func (o *Openings) IsNew(host string, f checks.Finding) bool {
	t, ok := o.Opened(host, f)
	return ok && o.scans[host] > 1 && t.Equal(o.last[host])
}

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
func carryOpen(prev map[openKey]time.Time, h HostSnapshot) map[openKey]time.Time {
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

func dayCount(n int) string {
	switch {
	case n < 1:
		return "today"
	case n == 1:
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}
