package allow

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
)

const sample = `# reviewed exceptions
ACC-002  *      nobet-scan   # scanning account
NET-001  web*   tcp/443
*        lab-*               # out of scope
UPD-002  db01
`

func TestParse(t *testing.T) {
	rules, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	if r := rules[0]; r.CheckID != "ACC-002" || r.Host != "*" || r.Match != "nobet-scan" || r.Reason != "scanning account" || r.Line != 2 {
		t.Errorf("rule 0: %+v", r)
	}

	for _, bad := range []string{"ACC-002\n", "nonsense web01\n", "ACC-002 [web\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", bad)
		}
	}
}

func TestApply(t *testing.T) {
	rules, _ := Parse(strings.NewReader(sample))
	l := &List{Path: "/home/me/.config/nobet/allowlist", Rules: rules}

	r := scan.HostResult{Host: "web01", Findings: []checks.Finding{
		{CheckID: "ACC-002", Title: "Passwordless sudo rule", Detail: "/etc/sudoers.d/nobet: nobet-scan  ALL=(ALL) NOPASSWD: ALL"},
		{CheckID: "ACC-002", Title: "Passwordless sudo rule", Detail: "/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: ALL"},
		{CheckID: "NET-001", Title: "1 other service(s) listening on all interfaces", Detail: "tcp/443"},
		{CheckID: "UPD-002", Title: "Reboot required"},
	}}
	l.Apply(&r)

	if len(r.Findings) != 2 || r.Findings[0].Detail != "/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: ALL" || r.Findings[1].CheckID != "UPD-002" {
		t.Errorf("kept findings: %+v", r.Findings)
	}
	if len(r.Suppressed) != 2 || r.Suppressed[0].Rule != "allowlist:2" || r.Suppressed[0].Reason != "scanning account" {
		t.Errorf("suppressed: %+v", r.Suppressed)
	}

	lab := scan.HostResult{Host: "lab-3", Findings: []checks.Finding{{CheckID: "SSH-001", Title: "x"}}}
	l.Apply(&lab)
	if len(lab.Findings) != 0 || len(lab.Suppressed) != 1 {
		t.Errorf("lab host: %+v", lab)
	}
}

func TestLoadMissing(t *testing.T) {
	if l, err := Load("/nonexistent/allowlist", false); err != nil || len(l.Rules) != 0 {
		t.Errorf("optional missing file: %v, %+v", err, l)
	}
	if _, err := Load("/nonexistent/allowlist", true); err == nil {
		t.Error("required missing file should fail")
	}
}
