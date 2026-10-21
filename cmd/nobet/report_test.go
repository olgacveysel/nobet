package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

func TestReportFromHistory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scans")
	facts := &collect.Facts{IsRoot: true, OSRelease: map[string]string{"PRETTY_NAME": "Debian 13"}}
	at := time.Date(2026, 10, 20, 3, 15, 0, 0, time.UTC)
	if _, err := store.Save(dir, []scan.HostResult{
		{Host: "web01", Facts: facts, Findings: []checks.Finding{{CheckID: "SSH-001", Severity: checks.High, Title: "Root can log in directly over SSH"}}},
		{Host: "db01", Error: "connection refused"},
	}, at); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	pdf, html := filepath.Join(out, "r.pdf"), filepath.Join(out, "r.html")
	if code := runReport([]string{"-history-dir", dir, "-pdf", pdf, "-html", html}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if b, _ := os.ReadFile(pdf); !strings.HasPrefix(string(b), "%PDF-") {
		t.Error("not a PDF")
	}
	b, _ := os.ReadFile(html)
	if !strings.Contains(string(b), "Root can log in directly over SSH") || !strings.Contains(string(b), "no successful scan in the history") {
		t.Error("the HTML report lacks web01's finding or db01's state")
	}
	if st, _ := os.Stat(pdf); st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Errorf("report mode %v, want 0600", st.Mode().Perm())
	}

	// -host narrows it; without an output or a history it refuses.
	if code := runReport([]string{"-history-dir", dir, "-html", html, "-host", "web*"}); code != exitOK {
		t.Fatalf("exit %d", code)
	}
	if b, _ := os.ReadFile(html); strings.Contains(string(b), "db01") {
		t.Error("-host web* still lists db01")
	}
	if code := runReport([]string{"-history-dir", dir}); code != exitUsage {
		t.Errorf("no output: exit %d", code)
	}
	if code := runReport([]string{"-history-dir", t.TempDir(), "-pdf", pdf}); code != exitUsage {
		t.Errorf("empty history: exit %d", code)
	}
	if code := runReport([]string{"-history-dir", dir, "-pdf", pdf, "-host", "nomatch*"}); code != exitUsage {
		t.Errorf("no matching host: exit %d", code)
	}
}

func TestParseSince(t *testing.T) {
	cases := map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "36h": 36 * time.Hour, "90m": 90 * time.Minute}
	for in, want := range cases {
		if got, err := parseSince(in); err != nil || got != want {
			t.Errorf("parseSince(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0d", "-1d", "xd", "soon", "-5h"} {
		if _, err := parseSince(bad); err == nil {
			t.Errorf("parseSince(%q) should fail", bad)
		}
	}
}
