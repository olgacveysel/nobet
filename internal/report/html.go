package report

import (
	_ "embed"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/rootmap"
	"github.com/olgacveysel/nobet/internal/scan"
)

//go:embed assets/wordmark.svg
var wordmarkSVG string

//go:embed assets/report.html.tmpl
var htmlTemplate string

var tmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"sev":   func(s checks.Severity) string { return s.String() },
}).Parse(htmlTemplate))

// HTMLMeta is report-level information shown in the header.
type HTMLMeta struct {
	Generated time.Time
	Version   string
}

type htmlHost struct {
	scan.HostResult
	Worst  string // worst severity name, "ok", or "error"
	Counts map[string]int
}

type htmlData struct {
	Meta     HTMLMeta
	Logo     template.HTML
	Hosts    []htmlHost
	Totals   map[string]int
	Severity []string
	Root     rootmap.Map
	HasRoot  bool
	Allowed  int
	Failed   int
}

// HTML writes a self-contained report (no external files, scripts or
// fonts) suitable for sharing with auditors or printing to PDF.
func HTML(w io.Writer, results []scan.HostResult, meta HTMLMeta) error {
	d := htmlData{
		Meta:     meta,
		Logo:     template.HTML(wordmarkSVG), // our own embedded asset
		Totals:   map[string]int{},
		Severity: []string{"critical", "high", "medium", "low", "info"},
	}
	for _, r := range results {
		h := htmlHost{HostResult: r, Counts: map[string]int{}}
		worst := checks.Severity(-1)
		for _, f := range r.Findings {
			h.Counts[f.Severity.String()]++
			d.Totals[f.Severity.String()]++
			if f.Severity > worst {
				worst = f.Severity
			}
		}
		switch {
		case r.Error != "":
			h.Worst = "error"
			d.Failed++
		case worst < checks.Low:
			h.Worst = "ok"
		default:
			h.Worst = worst.String()
		}
		d.Allowed += len(r.Suppressed)
		d.Hosts = append(d.Hosts, h)
		if r.Facts != nil {
			d.HasRoot = true
		}
	}
	// Worst hosts first, then by name.
	rank := map[string]int{"error": 0, "critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5, "ok": 6}
	sort.SliceStable(d.Hosts, func(i, j int) bool {
		if a, b := rank[d.Hosts[i].Worst], rank[d.Hosts[j].Worst]; a != b {
			return a < b
		}
		return d.Hosts[i].Host < d.Hosts[j].Host
	})
	if d.HasRoot {
		d.Root = rootmap.Build(results)
	}
	return tmpl.Execute(w, d)
}
