package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

func TestHTML(t *testing.T) {
	results := []scan.HostResult{
		{Host: "web01", OS: "Ubuntu 24.04", Privileged: true,
			Findings:   []checks.Finding{{CheckID: "SSH-001", Severity: checks.High, Title: "Root can log in directly over SSH", Detail: "PermitRootLogin yes", Fix: "Set 'PermitRootLogin no'"}},
			Suppressed: []scan.Suppressed{{Finding: checks.Finding{CheckID: "NET-001", Title: "tcp/443"}, Reason: "public web", Rule: "allowlist:3"}},
			Facts: &collect.Facts{IsRoot: true, Passwd: []collect.PasswdEntry{{Name: "root", UID: 0}},
				AuthKeys: []collect.AuthKey{{User: "root", Fingerprint: "SHA256:abc", Type: "ssh-ed25519", Comment: "<script>x</script>"}},
				Groups:   []collect.GroupEntry{}, SudoRights: map[string][]collect.SudoEntry{}}},
		{Host: "db01", Error: "connection refused"},
	}
	var buf bytes.Buffer
	if err := HTML(&buf, results, HTMLMeta{Generated: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC), Version: "test"}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"<svg", "web01", "PermitRootLogin yes", "connection refused", "public web", "SHA256:abc", "Root access map"} {
		if !strings.Contains(out, want) {
			t.Errorf("report is missing %q", want)
		}
	}
	if strings.Contains(out, "<script>x</script>") {
		t.Error("data from hosts must be HTML-escaped")
	}
	// The unreachable host sorts first.
	if strings.Index(out, `href="#host-db01"`) > strings.Index(out, `href="#host-web01"`) {
		t.Error("unreachable hosts should be listed first")
	}
}

func TestReportsShowOpenSince(t *testing.T) {
	old := checks.Finding{CheckID: "SSH-001", Severity: checks.High, Title: "Root can log in directly over SSH"}
	fresh := checks.Finding{CheckID: "ACC-002", Severity: checks.High, Title: "Passwordless sudo rule"}
	results := []scan.HostResult{{Host: "web01", Privileged: true, Findings: []checks.Finding{old, fresh}}}
	meta := HTMLMeta{Generated: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC), Version: "test",
		Opened: func(host string, f checks.Finding) (string, bool) {
			if f.CheckID == "ACC-002" {
				return "new in this scan", true
			}
			return "open since 2026-09-12 (40 days)", false
		}}
	var buf bytes.Buffer
	if err := HTML(&buf, results, meta); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`<span class="opened">open since 2026-09-12 (40 days)</span>`, `<span class="opened new">new in this scan</span>`} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report is missing %s", want)
		}
	}
	// Without a history, nothing is shown.
	buf.Reset()
	meta.Opened = nil
	if err := HTML(&buf, results, meta); err != nil || strings.Contains(buf.String(), `class="opened`) {
		t.Errorf("no history: %v", err)
	}
	buf.Reset()
	if err := PDF(&buf, results, HTMLMeta{Generated: meta.Generated, Opened: func(string, checks.Finding) (string, bool) { return "new in this scan", true }}); err != nil {
		t.Errorf("PDF: %v", err)
	}
}
