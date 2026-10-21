package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func TestPDF(t *testing.T) {
	var many []checks.Finding
	for i := 0; i < 60; i++ { // enough for several pages
		many = append(many, checks.Finding{CheckID: fmt.Sprintf("TST-%03d", i), Severity: checks.Severity(i % 5),
			Title:  "A finding with a long title that has to wrap onto a second line in the PDF layout, twice over",
			Detail: strings.Repeat("/very/long/path/without/spaces/", 12) + " and words", Fix: "Fix it"})
	}
	results := []scan.HostResult{
		{Host: "web01", OS: "Ubuntu 24.04", Privileged: true, Findings: many,
			Suppressed: []scan.Suppressed{{Finding: checks.Finding{CheckID: "NET-001", Title: "tcp/443"}, Reason: "public web"}},
			Skipped:    []scan.Skip{{CheckID: "UPD-001", Reason: "no cache"}},
			Facts: &collect.Facts{IsRoot: true, Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}},
				AuthKeys: []collect.AuthKey{{User: "root", Fingerprint: "SHA256:abc", Type: "ssh-ed25519", Comment: "ünïcödé 日本 \x07bell"}},
				Groups:   []collect.GroupEntry{}, SudoRights: map[string][]collect.SudoEntry{}}},
		{Host: "db01", Error: "connection refused"},
		{Host: "名前.example", OS: "Debian", Privileged: false},
	}
	var buf bytes.Buffer
	if err := PDF(&buf, results, HTMLMeta{Generated: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC), Version: "test"}); err != nil {
		t.Fatal(err)
	}
	out := buf.Bytes()
	if !bytes.HasPrefix(out, []byte("%PDF-")) || !bytes.Contains(out[len(out)-32:], []byte("%%EOF")) {
		t.Fatalf("not a PDF: %q ... %q", out[:16], out[len(out)-16:])
	}
	if pages := bytes.Count(out, []byte("/Type /Page\n")) + bytes.Count(out, []byte("/Type /Page ")); pages < 3 {
		t.Errorf("%d pages for 60 findings, want several", pages)
	}
}

func TestPDFCleansText(t *testing.T) {
	p, err := newPDFWriter(HTMLMeta{})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.clean("nöbet → ü\t日本\x00"); got != "nöbet → ü ??" {
		t.Errorf("clean = %q", got)
	}
	p.setFont(fontRegular, 9, colInk)
	for _, l := range p.wrap(strings.Repeat("x", 400), 100) {
		if w, _ := p.pdf.MeasureTextWidth(l); w > 100 {
			t.Errorf("line %q is %.0f wide", l, w)
		}
	}
}
