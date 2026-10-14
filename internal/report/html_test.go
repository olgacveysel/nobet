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
