package web

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

func TestOpenSincePages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scans")
	day := func(n int) time.Time { return time.Date(2026, 10, n, 3, 0, 0, 0, time.UTC) }
	facts := &collect.Facts{IsRoot: true}
	old := checks.Finding{CheckID: "SSH-002", Severity: checks.Medium, Title: "SSH password authentication is enabled"}
	mid := checks.Finding{CheckID: "UPD-002", Severity: checks.Medium, Title: "Reboot required"}
	fresh := checks.Finding{CheckID: "ACC-002", Severity: checks.High, Title: "Passwordless sudo rule", Detail: "/etc/sudoers.d/x"}
	for _, s := range []struct {
		n  int
		fs []checks.Finding
		e  string
	}{
		{1, []checks.Finding{old}, ""},
		{5, []checks.Finding{old, mid}, ""},
		{6, nil, "connection refused"}, // a failed scan says nothing
		{8, []checks.Finding{old, mid, fresh}, ""},
	} {
		r := scan.HostResult{Host: "web01", Facts: facts, Findings: s.fs, Error: s.e}
		if s.e != "" {
			r.Facts = nil
		}
		if _, err := store.Save(dir, []scan.HostResult{r}, day(s.n)); err != nil {
			t.Fatal(err)
		}
	}
	ix, err := buildIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := day(8).Add(6 * time.Hour)
	want := map[string]string{
		"SSH-002": "open since 2026-10-01 or earlier (7 days)",
		"UPD-002": "open since 2026-10-05 (3 days)",
		"ACC-002": "new in this scan",
	}
	for _, f := range []checks.Finding{old, mid, fresh} {
		if got := ix.withOpen("web01", f, now); got.Open != want[f.CheckID] || got.New != (f.CheckID == "ACC-002") {
			t.Errorf("%s: %q (new %v), want %q", f.CheckID, got.Open, got.New, want[f.CheckID])
		}
	}

	// A host scanned once shows no dates.
	one := filepath.Join(t.TempDir(), "scans")
	store.Save(one, []scan.HostResult{{Host: "db01", Facts: facts, Findings: []checks.Finding{old}}}, day(8))
	ix1, _ := buildIndex(one)
	if got := ix1.withOpen("db01", old, now); got.Open != "" {
		t.Errorf("single scan: %q", got.Open)
	}
}
