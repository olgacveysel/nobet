package store

import (
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func TestSaveLoadPrune(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	res := []scan.HostResult{
		{Host: "web01", Facts: &collect.Facts{IsRoot: true}, Findings: []checks.Finding{{CheckID: "SSH-001"}},
			Suppressed: []scan.Suppressed{{Finding: checks.Finding{CheckID: "ACC-002"}}}},
		{Host: "db01", Error: "connection refused"},
	}
	for i := 0; i < 3; i++ {
		if _, err := Save(dir, res, t0.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	if n := countSnapshots(t, dir); n != 3 {
		t.Fatalf("Walk: %d snapshots", n)
	}
	recent, hosts, err := Recent(dir, 10)
	if err != nil || len(hosts) != 2 {
		t.Fatalf("Recent: %v, hosts %v", err, hosts)
	}
	h := recent["web01"]
	if len(h) != 3 || len(h[0].Findings) != 2 || !h[0].Facts.IsRoot {
		t.Errorf("history: %+v", h)
	}
	if len(recent["db01"]) != 0 {
		t.Error("failed scans should not be in history")
	}
	if two, _, _ := Recent(dir, 2); len(two["web01"]) != 2 || !two["web01"][1].Time.Equal(t0.Add(2*time.Hour)) {
		t.Errorf("Recent(2) should keep the newest two, oldest first: %+v", two["web01"])
	}

	if err := Prune(dir, 2); err != nil {
		t.Fatal(err)
	}
	var first time.Time
	n := 0
	Walk(dir, func(s Snapshot) error {
		if n == 0 {
			first = s.Time
		}
		n++
		return nil
	})
	if n != 2 || !first.Equal(t0.Add(time.Hour)) {
		t.Errorf("after prune: %d snapshots, first at %v", n, first)
	}
}

func countSnapshots(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	if err := Walk(dir, func(Snapshot) error { n++; return nil }); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLoadMissingDir(t *testing.T) {
	recent, hosts, err := Recent(t.TempDir()+"/nope", 1)
	if err != nil || len(recent) != 0 || hosts != nil {
		t.Errorf("missing dir: %v, %v, %v", recent, hosts, err)
	}
}
