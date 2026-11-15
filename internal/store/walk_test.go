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
