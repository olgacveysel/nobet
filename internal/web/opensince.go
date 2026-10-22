package web

import (
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
)

// withOpen is a finding as the pages show it, with since when it has been
// open (store.Openings).
func (ix *index) withOpen(host string, f checks.Finding, now time.Time) hostFinding {
	hf := hostFinding{Severity: f.Severity.String(), CheckID: f.CheckID, Title: f.Title, Detail: f.Detail, Fix: f.Fix}
	hf.Open, hf.New = ix.openings.Text(host, f, now)
	return hf
}
