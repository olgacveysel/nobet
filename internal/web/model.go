package web

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/drift"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

// severities in display order; info is shown in host details only.
var severities = []string{"critical", "high", "medium", "low", "info"}

// index is everything derived from one version of the history directory.
// It is built in one pass over the history and keeps, per host, only the
// newest successful scan in full plus a summary row per scan, so memory
// does not grow with the length of the history. It is rebuilt only when
// the directory changes.
type index struct {
	hosts    []string                         // sorted
	latest   map[string]attempt               // newest scan attempt per host, failed or not
	current  map[string]store.HostSnapshot    // newest successful scan per host
	hist     map[string][]historyRow          // every successful scan per host, oldest first
	groups   []changeGroup                    // every scan-to-scan change set, newest first
	opened   map[string]map[openKey]time.Time // per host, when each current finding opened (opensince.go)
	lastScan time.Time
}

// attempt is when a host was last tried and why that failed, if it did.
type attempt struct {
	Time  time.Time
	Error string
}

// historyRow summarizes one successful scan of a host.
type historyRow struct {
	Time        time.Time
	Counts      map[string]int // active findings by severity
	Privileged  bool
	Allowlisted int
}

// changeGroup is what changed on one host between two successive scans.
type changeGroup struct {
	Host, Href string
	From, To   time.Time
	Changes    []drift.Change
}

func buildIndex(dir string) (*index, error) {
	ix := &index{
		latest:  map[string]attempt{},
		current: map[string]store.HostSnapshot{},
		hist:    map[string][]historyRow{},
		opened:  map[string]map[openKey]time.Time{},
	}
	err := store.Walk(dir, func(s store.Snapshot) error {
		if s.Time.After(ix.lastScan) {
			ix.lastScan = s.Time
		}
		for _, h := range s.Hosts {
			if _, seen := ix.latest[h.Host]; !seen {
				ix.hosts = append(ix.hosts, h.Host)
			}
			ix.latest[h.Host] = attempt{Time: h.Time, Error: h.Error}
			if h.Error != "" || h.Facts == nil {
				continue
			}
			if prev, ok := ix.current[h.Host]; ok {
				if d := drift.Compare(prev, h); len(d.Changes) > 0 {
					ix.groups = append(ix.groups, changeGroup{Host: h.Host, Href: hostHref(h.Host), From: d.From, To: d.To, Changes: d.Changes})
				}
			}
			ix.current[h.Host] = h
			ix.opened[h.Host] = carryOpen(ix.opened[h.Host], h)
			ix.hist[h.Host] = append(ix.hist[h.Host], historyRow{
				Time: h.Time, Counts: countBySeverity(h.Active()),
				Privileged: h.Facts.Privileged(), Allowlisted: len(h.Allowlisted),
			})
		}
		return nil
	})
	sort.Strings(ix.hosts)
	sort.SliceStable(ix.groups, func(i, j int) bool {
		if !ix.groups[i].To.Equal(ix.groups[j].To) {
			return ix.groups[i].To.After(ix.groups[j].To)
		}
		return ix.groups[i].Host < ix.groups[j].Host
	})
	return ix, err
}

func countBySeverity(fs []checks.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.Severity.String()]++
	}
	return m
}

func hostHref(name string) string { return "/host/" + url.PathEscape(name) }

// hostRow is one host's current state, as shown in the fleet table.
type hostRow struct {
	Name, Href  string
	OS          string
	Last        time.Time // newest scan attempt
	LastOK      time.Time // newest successful scan; zero if none
	Error       string    // set when the newest attempt failed
	Stale       bool      // no successful scan within the stale period
	Privileged  bool
	Counts      map[string]int
	Allowlisted int
	Status      string // critical, high, medium, low, ok, error or never
}

func (ix *index) row(host string, now time.Time, staleAfter time.Duration) hostRow {
	latest := ix.latest[host]
	r := hostRow{Name: host, Href: hostHref(host), Last: latest.Time, Error: latest.Error, Counts: map[string]int{}}
	if cur, ok := ix.current[host]; ok {
		last := ix.hist[host][len(ix.hist[host])-1]
		r.LastOK = cur.Time
		r.OS = cur.Facts.OSRelease["PRETTY_NAME"]
		r.Privileged, r.Counts, r.Allowlisted = last.Privileged, last.Counts, last.Allowlisted
	}
	r.Stale = r.LastOK.IsZero() || now.Sub(r.LastOK) > staleAfter
	switch {
	case r.Error != "" && r.LastOK.IsZero():
		r.Status = "never"
	case r.Error != "":
		r.Status = "error"
	default:
		r.Status = "ok"
		for _, s := range severities[:4] {
			if r.Counts[s] > 0 {
				r.Status = s
				break
			}
		}
	}
	return r
}

// statusRank sorts hosts that need attention first.
var statusRank = map[string]int{"never": 0, "error": 1, "critical": 2, "high": 3, "medium": 4, "low": 5, "ok": 6}

func (ix *index) rows(now time.Time, staleAfter time.Duration) []hostRow {
	rows := make([]hostRow, 0, len(ix.hosts))
	for _, h := range ix.hosts {
		rows = append(rows, ix.row(h, now, staleAfter))
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if a, b := statusRank[rows[i].Status], statusRank[rows[j].Status]; a != b {
			return a < b
		}
		return rows[i].Name < rows[j].Name
	})
	return rows
}

// trend is a stacked bar chart of the fleet's active findings per day,
// drawn as inline SVG so the page needs no script.
type trend struct {
	Width, Height int
	Bars          []trendBar
	Days          int
}

type trendBar struct {
	Label string // tooltip
	Segs  []trendSeg
}

type trendSeg struct {
	X, Y, W, H int
	Sev        string
}

const (
	trendHeight = 96
	barWidth    = 14
	barGap      = 4
)

// buildTrend counts, for each of the last days days, the active findings
// of every host's newest successful scan up to the end of that day.
func (ix *index) buildTrend(now time.Time, days int) *trend {
	if len(ix.hist) == 0 {
		return nil
	}
	first := now
	for _, hist := range ix.hist {
		if t := hist[0].Time; t.Before(first) {
			first = t
		}
	}
	today := now.UTC().Truncate(24 * time.Hour)
	start := today.AddDate(0, 0, -(days - 1))
	if f := first.UTC().Truncate(24 * time.Hour); f.After(start) {
		start = f
	}
	type day struct {
		date   time.Time
		counts map[string]int
		total  int
	}
	var ds []day
	max := 0
	for d := start; !d.After(today); d = d.AddDate(0, 0, 1) {
		end := d.AddDate(0, 0, 1)
		c := map[string]int{}
		total := 0
		for _, hist := range ix.hist {
			i := sort.Search(len(hist), func(i int) bool { return !hist[i].Time.Before(end) }) - 1
			if i < 0 {
				continue
			}
			for _, s := range severities[:4] {
				c[s] += hist[i].Counts[s]
				total += hist[i].Counts[s]
			}
		}
		ds = append(ds, day{d, c, total})
		if total > max {
			max = total
		}
	}
	t := &trend{Width: len(ds)*(barWidth+barGap) - barGap, Height: trendHeight, Days: len(ds)}
	for i, d := range ds {
		b := trendBar{Label: fmt.Sprintf("%s: %d critical, %d high, %d medium, %d low",
			d.date.Format("2006-01-02"), d.counts["critical"], d.counts["high"], d.counts["medium"], d.counts["low"])}
		x, y := i*(barWidth+barGap), trendHeight
		for _, s := range severities[:4] {
			if d.counts[s] == 0 || max == 0 {
				continue
			}
			h := d.counts[s] * trendHeight / max
			if h < 1 {
				h = 1
			}
			y -= h
			b.Segs = append(b.Segs, trendSeg{X: x, Y: y, W: barWidth, H: h, Sev: s})
		}
		if len(b.Segs) == 0 { // a day with no findings still gets a baseline
			b.Segs = []trendSeg{{X: x, Y: trendHeight - 1, W: barWidth, H: 1, Sev: "none"}}
		}
		t.Bars = append(t.Bars, b)
	}
	return t
}

// rootMap builds the access map from every host's newest successful scan,
// noting hosts whose newest attempt failed.
func (ix *index) rootMap() rootmap.Map {
	var results []scan.HostResult
	var notes []rootmap.Gap
	for _, h := range ix.hosts {
		latest := ix.latest[h]
		ok, scanned := ix.current[h]
		if !scanned {
			results = append(results, scan.HostResult{Host: h, Error: latest.Error})
			continue
		}
		results = append(results, scan.HostResult{Host: h, Facts: ok.Facts})
		if latest.Error != "" {
			notes = append(notes, rootmap.Gap{Host: h, Reason: fmt.Sprintf("newest scan (%s) failed: %s; showing the scan from %s",
				latest.Time.UTC().Format("2006-01-02 15:04"), latest.Error, ok.Time.UTC().Format("2006-01-02 15:04"))})
		}
	}
	m := rootmap.Build(results)
	m.Gaps = append(m.Gaps, notes...)
	return m
}

// ago describes how long ago t was.
func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case t.IsZero():
		return "never"
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

// human formats a period such as -stale for people: "2 days", "12 h".
func human(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == day:
		return "1 day"
	case d > day && d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d h", d/time.Hour)
	}
	return d.String()
}

func routeText(rs []rootmap.Route) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.Via
	}
	return strings.Join(parts, "; ")
}
