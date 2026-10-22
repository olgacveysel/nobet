package allow

import (
	"strings"
	"testing"
	"time"

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

func TestUntil(t *testing.T) {
	rules, err := Parse(strings.NewReader("CTR-001  *  traefik until=2026-10-31  # needs the socket\n" +
		"NET-001  web*  until=2026-10-20 tcp/443\n" +
		"ACC-002  *  nobet-scan\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r := rules[0]; r.Match != "traefik" || r.Until != "2026-10-31" || r.Reason != "needs the socket" {
		t.Errorf("rule 0: %+v", r)
	}
	if r := rules[1]; r.Match != "tcp/443" || r.Until != "2026-10-20" {
		t.Errorf("until in the middle: %+v", r)
	}
	for _, bad := range []string{"CTR-001 * until=2026-13-01\n", "CTR-001 * until=soon\n", "CTR-001 * until=2026-10-01 until=2026-11-01\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "until=YYYY-MM-DD") {
			t.Errorf("Parse(%q): %v", bad, err)
		}
	}

	l := &List{Path: "/etc/nobet/allowlist", Rules: rules}
	findings := func() *scan.HostResult {
		return &scan.HostResult{Host: "web01", Findings: []checks.Finding{
			{CheckID: "CTR-001", Title: "Container traefik can take over the host"},
			{CheckID: "NET-001", Title: "1 other service(s) listening on all interfaces", Detail: "tcp/443"},
		}}
	}
	day := func(s string) time.Time { d, _ := time.Parse(time.DateOnly, s); return d.Add(15 * time.Hour) }

	// The last day still counts; the day after, the rule is gone.
	r := findings()
	l.ApplyAt(r, day("2026-10-20"))
	if len(r.Findings) != 0 || r.Suppressed[0].Until != "2026-10-31" || r.Suppressed[1].Until != "2026-10-20" {
		t.Errorf("on 2026-10-20: %+v", r)
	}
	r = findings()
	l.ApplyAt(r, day("2026-10-21"))
	if len(r.Findings) != 1 || r.Findings[0].CheckID != "NET-001" || len(r.Suppressed) != 1 {
		t.Errorf("on 2026-10-21: %+v", r)
	}

	notes := l.Notes(day("2026-10-21"))
	want := []string{
		"rule allowlist:1 (CTR-001 * traefik) covers findings until 2026-10-31 (11 more day(s)); review it",
		"rule allowlist:2 (NET-001 web* tcp/443) ended on 2026-10-20; the findings it covered count again",
	}
	if strings.Join(notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(notes, "\n"), strings.Join(want, "\n"))
	}
	if n := l.Notes(day("2026-10-31")); len(n) != 2 || !strings.Contains(n[0], "(1 more day(s))") {
		t.Errorf("last day: %v", n)
	}
	if n := l.Notes(day("2026-09-01")); len(n) != 0 {
		t.Errorf("far ahead: %v", n)
	}
}
