package web

import (
	"net/http"
	"net/url"
	"sort"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
)

// checkRow is one check across every host's newest successful scan.
type checkRow struct {
	ID, Title, Href string
	Worst           string // worst severity among active findings; "" if none
	Hosts           int    // hosts with an active finding
	Allowed         int    // hosts where the allowlist covered it
	Skipped         int    // hosts where it could not run
}

func checkHref(id string) string { return "/check/" + url.PathEscape(id) }

// checkRows returns the checks that found something on at least one host,
// worst first, then by how many hosts.
func (ix *index) checkRows() []checkRow {
	var out []checkRow
	for _, c := range checks.All() {
		r := checkRow{ID: c.ID, Title: c.Title, Href: checkHref(c.ID)}
		worst := checks.Severity(-1)
		for _, h := range ix.hosts {
			cur, ok := ix.current[h]
			if !ok {
				continue
			}
			found := false
			for _, f := range cur.Active() {
				if f.CheckID == c.ID {
					found = true
					if f.Severity > worst {
						worst = f.Severity
					}
				}
			}
			if found {
				r.Hosts++
			}
			for _, s := range cur.Allowlisted {
				if s.CheckID == c.ID {
					r.Allowed++
					break
				}
			}
			for _, s := range cur.Skipped {
				if s.CheckID == c.ID {
					r.Skipped++
					break
				}
			}
		}
		if r.Hosts == 0 {
			continue
		}
		r.Worst = worst.String()
		out = append(out, r)
	}
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(out, func(i, j int) bool {
		if a, b := rank[out[i].Worst], rank[out[j].Worst]; a != b {
			return a < b
		}
		return out[i].Hosts > out[j].Hosts
	})
	return out
}

type checkHost struct {
	Host, Href string
	Findings   []hostFinding
}

type checkAllowed struct {
	Host, Href string
	Items      []scan.Suppressed
}

type checkSkipped struct {
	Host, Href, Reason string
}

type checkPage struct {
	page
	ID, Title string
	Affected  []checkHost
	Allowed   []checkAllowed
	Skipped   []checkSkipped
	Passed    int // hosts where the check ran and found nothing
	Scanned   int // hosts with a successful scan
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	ix, ok := s.index(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	var title string
	for _, c := range checks.All() {
		if c.ID == id {
			title = c.Title
		}
	}
	if title == "" {
		s.message(w, r, http.StatusNotFound, "Unknown check", "There is no check "+id+"; `nobet checks` lists them.")
		return
	}
	p := checkPage{page: s.page(r, ix, id+" "+title, "fleet"), ID: id, Title: title}
	for _, h := range ix.hosts {
		cur, ok := ix.current[h]
		if !ok {
			continue
		}
		p.Scanned++
		href := hostHref(h)
		var fs []hostFinding
		for _, f := range cur.Active() {
			if f.CheckID == id {
				fs = append(fs, hostFinding{f.Severity.String(), f.CheckID, f.Title, f.Detail, f.Fix})
			}
		}
		var allowed []scan.Suppressed
		for _, a := range cur.Allowlisted {
			if a.CheckID == id {
				allowed = append(allowed, a)
			}
		}
		skipped := ""
		for _, sk := range cur.Skipped {
			if sk.CheckID == id {
				skipped = sk.Reason
			}
		}
		switch {
		case len(fs) > 0:
			p.Affected = append(p.Affected, checkHost{Host: h, Href: href, Findings: fs})
		case skipped != "":
			p.Skipped = append(p.Skipped, checkSkipped{Host: h, Href: href, Reason: skipped})
		case len(allowed) == 0:
			p.Passed++
		}
		if len(allowed) > 0 {
			p.Allowed = append(p.Allowed, checkAllowed{Host: h, Href: href, Items: allowed})
		}
	}
	s.render(w, http.StatusOK, "check", p)
}
