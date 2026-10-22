package web

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/queue"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

var now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func webFacts(extraKey bool) *collect.Facts {
	f := &collect.Facts{
		IsRoot:    true,
		OSRelease: map[string]string{"PRETTY_NAME": "Ubuntu 24.04 LTS"},
		SSHD:      map[string][]string{"permitrootlogin": {"prohibit-password"}},
		Passwd:    []collect.PasswdEntry{{Name: "root", UID: 0}, {Name: "deploy", UID: 1000, GID: 1000}},
		Groups:    []collect.GroupEntry{{Name: "deploy", GID: 1000}},
		Shadow:    []collect.ShadowEntry{{User: "deploy", Password: collect.PasswordSet}},
		SudoRights: map[string][]collect.SudoEntry{
			"deploy": {{RunAs: "ALL", NoPasswd: true, Commands: []string{"ALL"}}},
		},
		AuthKeys: []collect.AuthKey{{User: "deploy", Fingerprint: "SHA256:laptopkey", Type: "ssh-ed25519", Comment: "veysel@laptop"}},
	}
	if extraKey {
		f.AuthKeys = append(f.AuthKeys, collect.AuthKey{User: "root", Fingerprint: "SHA256:<script>alert(1)</script>", Type: "ssh-ed25519", Comment: "intruder@x"})
	}
	return f
}

// history writes three scans: web01 gains a key and a finding, db01
// becomes unreachable, and new01 has never been scanned successfully.
func history(t *testing.T, dir string) {
	t.Helper()
	high := checks.Finding{CheckID: "ACC-002", Severity: checks.High, Title: "Passwordless sudo for ALL commands", Detail: "/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: ALL", Fix: "Limit NOPASSWD"}
	allowed := scan.Suppressed{Finding: checks.Finding{CheckID: "NET-001", Severity: checks.Info, Title: "1 other service(s) listening on all interfaces", Detail: "tcp/443"}, Reason: "public web", Rule: "allowlist:3", Until: "2027-01-31"}
	scans := []struct {
		at      time.Time
		results []scan.HostResult
	}{
		{now.Add(-50 * time.Hour), []scan.HostResult{
			{Host: "web01", Privileged: true, Facts: webFacts(false), Findings: []checks.Finding{}, Suppressed: []scan.Suppressed{allowed}},
			{Host: "db01", Privileged: true, Facts: webFacts(false), Findings: []checks.Finding{high}},
		}},
		{now.Add(-2 * time.Hour), []scan.HostResult{
			{Host: "web01", Privileged: true, Facts: webFacts(true), Findings: []checks.Finding{high}, Suppressed: []scan.Suppressed{allowed},
				Skipped: []scan.Skip{{CheckID: "UPD-001", Reason: "apk package index cache is missing"}}},
			{Host: "db01", Error: "dial tcp 10.0.0.5:22: connection refused"},
			{Host: "new01", Error: "host key for new01:22 is not in known_hosts"},
		}},
	}
	for _, s := range scans {
		if _, err := store.Save(dir, s.results, s.at); err != nil {
			t.Fatal(err)
		}
	}
}

func newServer(t *testing.T, dir string, logw io.Writer) http.Handler {
	t.Helper()
	opts := Options{HistoryDir: dir, Version: "test", Now: func() time.Time { return now }, UserHeader: "X-Forwarded-User"}
	if logw != nil {
		opts.Log = log.New(logw, "", 0)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestPages(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	var logs bytes.Buffer
	h := newServer(t, dir, &logs)

	cases := []struct {
		path   string
		status int
		want   []string
	}{
		{"/", 200, []string{"web01", "db01", "new01", "never scanned", "unreachable", "<svg", "Recent changes", "intruder@x"}},
		{"/host/web01", 200, []string{"Passwordless sudo for ALL commands", "Fix: Limit NOPASSWD", "public web", "allowlist:3, until 2027-01-31",
			"apk package index cache is missing", "Scan history", "intruder@x"}},
		{"/host/db01", 200, []string{"connection refused", "last successful scan"}},
		{"/host/new01", 200, []string{"not in known_hosts"}},
		{"/host/nope", 404, []string{"Unknown host"}},
		{"/changes", 200, []string{"web01", "key", "intruder@x"}},
		{"/changes?days=1", 200, []string{"web01"}},
		{"/changes?days=bogus", 200, []string{"30 days"}},
		{"/root", 200, []string{"SHA256:laptopkey", "veysel@laptop", "sudo ALL, no password", "newest scan", "not scanned"}},
		{"/static/style.css", 200, []string{"--navy"}},
		{"/static/logo.svg", 200, []string{"<svg"}},
		{"/healthz", 200, []string{"ok"}},
		{"/static/", 404, nil},
		{"/favicon.ico", 301, nil},
		{"/nope", 404, nil},
	}
	for _, c := range cases {
		rec := get(t, h, "GET", c.path)
		body := rec.Body.String()
		if rec.Code != c.status {
			t.Errorf("GET %s: status %d, want %d", c.path, rec.Code, c.status)
		}
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("GET %s: body lacks %q", c.path, w)
			}
		}
		if strings.Contains(body, "<script>") {
			t.Errorf("GET %s: unescaped <script> in output", c.path)
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("GET %s: CSP %q", c.path, csp)
		}
		wantCache := "no-store"
		if strings.HasPrefix(c.path, "/static/") && c.status == 200 {
			wantCache = "public, max-age=3600"
		}
		if rec.Header().Get("Cache-Control") != wantCache || rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("GET %s: headers %v", c.path, rec.Header())
		}
	}
	// The page for db01's newest attempt explains the failure but still
	// shows the findings of its last good scan.
	if body := get(t, h, "GET", "/host/db01").Body.String(); !strings.Contains(body, "Passwordless sudo") {
		t.Error("db01 should show its last successful scan")
	}

	if !strings.Contains(logs.String(), `GET /host/web01 200`) || !strings.Contains(logs.String(), `user="alice@example.com"`) {
		t.Errorf("request log:\n%s", logs.String())
	}
}

func TestReadOnlyMethods(t *testing.T) {
	h := newServer(t, t.TempDir(), nil)
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if rec := get(t, h, m, "/"); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /: %d", m, rec.Code)
		}
	}
	if rec := get(t, h, "HEAD", "/"); rec.Code != 200 {
		t.Errorf("HEAD /: %d", rec.Code)
	}
}

func TestEmptyAndBrokenHistory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "scans")
	rec := get(t, newServer(t, missing, nil), "GET", "/")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "No scans yet") {
		t.Errorf("empty history: %d\n%s", rec.Code, rec.Body.String())
	}
	if rec := get(t, newServer(t, missing, nil), "GET", "/root"); rec.Code != 200 {
		t.Errorf("empty root map: %d", rec.Code)
	}

	file := filepath.Join(t.TempDir(), "not-a-dir")
	os.WriteFile(file, []byte("x"), 0o600)
	rec = get(t, newServer(t, file, nil), "GET", "/")
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "Scan history unavailable") || strings.Contains(rec.Body.String(), file) {
		t.Errorf("unreadable history: %d\n%s", rec.Code, rec.Body.String())
	}
}

func TestReloadsWhenHistoryChanges(t *testing.T) {
	dir := t.TempDir()
	h := newServer(t, dir, nil)
	if body := get(t, h, "GET", "/").Body.String(); !strings.Contains(body, "No scans yet") {
		t.Fatal("expected the empty state first")
	}
	if _, err := store.Save(dir, []scan.HostResult{{Host: "late01", Facts: webFacts(false)}}, now); err != nil {
		t.Fatal(err)
	}
	if body := get(t, h, "GET", "/").Body.String(); !strings.Contains(body, "late01") {
		t.Error("a new scan should show up without a restart")
	}
}

func TestTrend(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	ix, err := buildIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	tr := ix.buildTrend(now, 30)
	// Scans span three calendar days: Oct 12, 13 (no scan, carried over)
	// and 14.
	if tr == nil || len(tr.Bars) != 3 {
		t.Fatalf("trend: %+v", tr)
	}
	// db01's newest scan failed; its last known state still counts.
	if !strings.Contains(tr.Bars[2].Label, "2026-10-14: 0 critical, 2 high") {
		t.Errorf("today: %q", tr.Bars[2].Label)
	}
	for _, b := range tr.Bars {
		for _, s := range b.Segs {
			if s.Y < 0 || s.H < 1 || s.Y+s.H > trendHeight {
				t.Errorf("segment out of bounds: %+v", s)
			}
		}
	}
}

func TestHuman(t *testing.T) {
	for d, want := range map[time.Duration]string{48 * time.Hour: "2 days", 24 * time.Hour: "1 day", 12 * time.Hour: "12 h", 90 * time.Minute: "1h30m0s"} {
		if got := human(d); got != want {
			t.Errorf("human(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestAgo(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Second: "just now", 5 * time.Minute: "5 min ago", 3 * time.Hour: "3 h ago", 72 * time.Hour: "3 days ago"} {
		if got := ago(now, now.Add(-d)); got != want {
			t.Errorf("ago(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestMetrics(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	if rec := get(t, newServer(t, dir, nil), "GET", "/metrics"); rec.Code != http.StatusNotFound {
		t.Errorf("metrics are opt-in: got %d", rec.Code)
	}
	s, err := New(Options{HistoryDir: dir, Version: "test", Now: func() time.Time { return now }, Metrics: true})
	if err != nil {
		t.Fatal(err)
	}
	rec := get(t, s.Handler(), "GET", "/metrics")
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("got %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{
		"# TYPE nobet_host_findings gauge\n",
		`nobet_build_info{version="test"} 1`,
		"nobet_hosts 3\n",
		`nobet_host_up{host="web01"} 1`,
		`nobet_host_up{host="db01"} 0`,
		`nobet_host_stale{host="new01"} 1`,
		`nobet_host_findings{host="web01",severity="high"} 1`,
		`nobet_host_findings{host="db01",severity="high"} 1`, // newest successful scan, 50 h old
		`nobet_host_stale{host="db01"} 1`,
		`nobet_host_allowlisted_findings{host="web01"} 1`,
		"nobet_root_keys 2\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `nobet_host_last_success_timestamp_seconds{host="new01"}`) {
		t.Error("a host never scanned successfully has no last-success time")
	}
	if strings.Contains(body, "unclaimed") {
		t.Error("unclaimed keys need a keys file")
	}
	if got := labelValue("a\"b\\c\nd"); got != `a\"b\\c\nd` {
		t.Errorf("labelValue = %s", got)
	}
}

// The keys file is read on every view of the root page.
func TestRootPageOwners(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	keysFile := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(keysFile, []byte("alice SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{HistoryDir: dir, Version: "test", Now: func() time.Time { return now }, KeysFile: keysFile})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	body := get(t, h, "GET", "/root").Body.String()
	for _, want := range []string{"Key owners come from <code>" + keysFile, "2 key(s) with root access have no owner", "no known owner"} {
		if !strings.Contains(body, want) {
			t.Errorf("root page lacks %q", want)
		}
	}
	if err := os.WriteFile(keysFile, []byte("alice not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if body := get(t, h, "GET", "/root").Body.String(); !strings.Contains(body, "<b>keys file</b>: "+keysFile+": line 1") {
		t.Errorf("a broken keys file should show as incomplete:\n%s", body)
	}
}

func TestReportDownloads(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	h := newServer(t, dir, nil)
	pdf := get(t, h, "GET", "/report.pdf")
	if pdf.Code != 200 || pdf.Header().Get("Content-Type") != "application/pdf" ||
		!strings.HasPrefix(pdf.Header().Get("Content-Disposition"), `attachment; filename="nobet-report-2026-10-14.pdf"`) ||
		!strings.HasPrefix(pdf.Body.String(), "%PDF-") {
		t.Errorf("PDF: %d %q %q", pdf.Code, pdf.Header().Get("Content-Type"), pdf.Header().Get("Content-Disposition"))
	}
	html := get(t, h, "GET", "/report.html")
	body := html.Body.String()
	if html.Code != 200 || !strings.Contains(html.Header().Get("Content-Disposition"), "attachment") ||
		!strings.Contains(body, "web01") || !strings.Contains(body, "Passwordless sudo for ALL commands") || !strings.Contains(body, "db01") {
		t.Errorf("HTML: %d", html.Code)
	}
	if fleet := get(t, h, "GET", "/").Body.String(); !strings.Contains(fleet, `href="/report.pdf"`) {
		t.Error("the fleet page should link the reports")
	}
}

func scanServer(t *testing.T, opts Options) (http.Handler, string) {
	t.Helper()
	dir, qdir := t.TempDir(), t.TempDir()
	history(t, dir)
	opts.HistoryDir, opts.ScanQueue, opts.Version = dir, qdir, "test"
	opts.Now = func() time.Time { return now }
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler(), qdir
}

func post(t *testing.T, h http.Handler, path, form string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-Forwarded-User", "alice@example.com")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestScanRequests(t *testing.T) {
	var audit bytes.Buffer
	h, qdir := scanServer(t, Options{UserHeader: "X-Forwarded-User", Audit: &audit})
	if body := get(t, h, "GET", "/").Body.String(); !strings.Contains(body, `<form method="post" action="/scan">`) || !strings.Contains(body, "Scan all hosts now") {
		t.Fatal("the fleet page should offer a scan")
	}
	if body := get(t, h, "GET", "/host/web01").Body.String(); !strings.Contains(body, `name="host" value="web01"`) {
		t.Error("a host page should offer to rescan that host")
	}

	// A form posted from another site is refused before it is read.
	if rec := post(t, h, "/scan", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST: %d", rec.Code)
	}
	if rec := post(t, h, "/scan", "host=nope", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown host: %d", rec.Code)
	}

	rec := post(t, h, "/scan", "host=web01", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/host/web01" {
		t.Fatalf("scan request: %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	p, err := queue.List(qdir)
	if err != nil || len(p) != 1 || p[0].User != "alice@example.com" || strings.Join(p[0].Hosts, ",") != "web01" {
		t.Fatalf("queue: %+v %v", p, err)
	}
	if rec := post(t, h, "/scan", "", nil); rec.Code != http.StatusConflict {
		t.Errorf("second request while one waits: %d", rec.Code)
	}
	if body := get(t, h, "GET", "/").Body.String(); !strings.Contains(body, "Scan queued, waiting for the scanner (web01): asked by alice@example.com") || strings.Contains(body, "Scan all hosts now") {
		t.Error("the fleet page should show the waiting request instead of the button")
	}
	if !strings.Contains(audit.String(), `"event":"scan_requested","user":"alice@example.com","method":"POST","path":"/scan","status":303`) ||
		!strings.Contains(audit.String(), `"reason":"web01"`) {
		t.Errorf("audit log:\n%s", audit.String())
	}

	// The scanner finishes it.
	claimed, _ := queue.Claim(qdir)
	queue.Finish(qdir, []queue.Done{{Request: claimed[0], Finished: now, Scanned: []string{"web01"}}})
	if body := get(t, h, "GET", "/").Body.String(); !strings.Contains(body, "Last scan asked for here: by alice@example.com (web01), finished") {
		t.Error("the fleet page should show the last finished request")
	}
}

func TestScanRequestsRestricted(t *testing.T) {
	h, qdir := scanServer(t, Options{UserHeader: "X-Forwarded-User", ScanUsers: []string{"ops@example.com"}})
	if body := get(t, h, "GET", "/").Body.String(); strings.Contains(body, "Scan all hosts now") {
		t.Error("alice may not ask for scans and should not get the button")
	}
	if rec := post(t, h, "/scan", "", nil); rec.Code != http.StatusForbidden {
		t.Errorf("not allowed: %d", rec.Code)
	}
	if rec := post(t, h, "/scan", "", map[string]string{"X-Forwarded-User": "OPS@example.com"}); rec.Code != http.StatusSeeOther {
		t.Errorf("allowed user: %d", rec.Code)
	}
	if p, _ := queue.List(qdir); len(p) != 1 || len(p[0].Hosts) != 0 {
		t.Errorf("queue: %+v", p)
	}
	// Without -scan-queue there is nothing to post to.
	plain := newServer(t, t.TempDir(), nil)
	if rec := post(t, plain, "/scan", "", nil); rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("scan requests off: %d", rec.Code)
	}
}

func TestCheckPage(t *testing.T) {
	dir := t.TempDir()
	history(t, dir)
	h := newServer(t, dir, nil)
	fleet := get(t, h, "GET", "/").Body.String()
	if !strings.Contains(fleet, "Findings by check") || !strings.Contains(fleet, `<a href="/check/ACC-002"><code>ACC-002</code></a>`) {
		t.Error("the fleet page should list findings by check")
	}
	if !strings.Contains(get(t, h, "GET", "/host/web01").Body.String(), `href="/check/ACC-002"`) {
		t.Error("a host page should link each finding's check")
	}
	rec := get(t, h, "GET", "/check/ACC-002")
	body := rec.Body.String()
	// web01 and db01 (its last successful scan) both have it.
	if rec.Code != 200 || !strings.Contains(body, "2 of 2 host(s) have findings") || !strings.Contains(body, `<a href="/host/web01">web01</a>`) {
		t.Errorf("check page: %d\n%s", rec.Code, body)
	}
	// NET-001 is allowlisted on web01, UPD-001 skipped there.
	if body := get(t, h, "GET", "/check/NET-001").Body.String(); !strings.Contains(body, "public web") {
		t.Error("allowlisted occurrences should be listed with their reason")
	}
	if body := get(t, h, "GET", "/check/UPD-001").Body.String(); !strings.Contains(body, "apk package index cache is missing") {
		t.Error("hosts that could not run the check should be listed")
	}
	if rec := get(t, h, "GET", "/check/NOPE-1"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown check: %d", rec.Code)
	}
}
