package store

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

// History written before host text was cleaned comes back clean, and
// files Walk cannot use are reported, not dropped in silence.
func TestWalkCleansAndReports(t *testing.T) {
	dir := t.TempDir()
	evil := "me@laptop\x1b]0;owned\x07\x1b[2J"
	res := []scan.HostResult{{Host: "web01", Facts: &collect.Facts{IsRoot: true,
		AuthKeys: []collect.AuthKey{{User: "root", Comment: evil}}},
		Findings: []checks.Finding{{CheckID: "ACC-006", Detail: evil}}}}
	if _, err := Save(dir, res, time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "20260102T000000Z.json"), []byte("{not json"), 0o600)
	os.WriteFile(filepath.Join(dir, "20260103T000000Z.json"), []byte(`{"version":99,"hosts":[]}`), 0o600)

	var skipped []string
	OnSkip = func(path, why string) { skipped = append(skipped, filepath.Base(path)+": "+why) }
	defer func() { OnSkip = nil }()
	var got []string
	err := Walk(dir, func(s Snapshot) error {
		for _, h := range s.Hosts {
			got = append(got, h.Findings[0].Detail, h.Facts.AuthKeys[0].Comment)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range got {
		if strings.ContainsRune(s, 0x1b) || strings.ContainsRune(s, 0x07) || !strings.HasPrefix(s, "me@laptop?]0;owned?") {
			t.Errorf("not cleaned: %q", s)
		}
	}
	sort.Strings(skipped)
	if len(skipped) != 2 || !strings.Contains(skipped[0], "not a scan snapshot") || !strings.Contains(skipped[1], "snapshot format 99") {
		t.Errorf("skipped: %q", skipped)
	}

	// WarnOnce reports a file once, however often the history is read.
	var lines []string
	warn := WarnOnce(func(f string, a ...any) { lines = append(lines, f) })
	warn("/x/a.json", "bad")
	warn("/x/a.json", "bad")
	warn("/x/b.json", "bad")
	if len(lines) != 2 {
		t.Errorf("WarnOnce printed %d lines", len(lines))
	}
}

// Rescanning one host many times pushes out that host's older scans only;
// the fleet's scans stay. Scans older than the age limit go regardless.
func TestPrunePerHostAndAge(t *testing.T) {
	dir := t.TempDir()
	t0 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	ok := func(host string) scan.HostResult {
		return scan.HostResult{Host: host, Facts: &collect.Facts{}, Findings: []checks.Finding{}}
	}
	fleet := []scan.HostResult{ok("web01"), ok("db01"), ok("mail01")}
	for i := 0; i < 3; i++ { // three full scans, a day apart
		Save(dir, fleet, t0.Add(time.Duration(i)*24*time.Hour))
	}
	for i := 0; i < 10; i++ { // then ten rescans of web01 alone
		Save(dir, []scan.HostResult{ok("web01")}, t0.Add(72*time.Hour+time.Duration(i)*time.Minute))
	}
	count := func() map[string]int {
		n := map[string]int{}
		Walk(dir, func(s Snapshot) error {
			for _, h := range s.Hosts {
				n[h.Host]++
			}
			return nil
		})
		return n
	}
	if err := Prune(dir, 3, 0, t0.Add(100*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// web01 keeps its three newest rescans, and is in the full scans the
	// others keep: a file is kept or deleted whole.
	if n := count(); n["db01"] != 3 || n["mail01"] != 3 || n["web01"] != 6 {
		t.Errorf("after rescans, per host: %v (db01 and mail01 must keep all three full scans)", n)
	}
	// 30 days on, with a 7-day limit, everything is too old.
	if err := Prune(dir, 3, 7*24*time.Hour, t0.Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := count(); len(n) != 0 {
		t.Errorf("after the age limit: %v", n)
	}
	// A file nobet cannot read is kept, until it is old.
	bad := filepath.Join(dir, "20261101T000000.000Z.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	Prune(dir, 1, 0, time.Now())
	if _, err := os.Stat(bad); err != nil {
		t.Error("an unreadable file was pruned by count")
	}
	os.Chtimes(bad, t0, t0)
	Prune(dir, 1, 24*time.Hour, t0.Add(48*time.Hour))
	if _, err := os.Stat(bad); err == nil {
		t.Error("an old unreadable file was kept")
	}
}
