package web

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
	"github.com/olgacveysel/nobet/internal/store"
)

func TestCarryOpen(t *testing.T) {
	day := func(n int) time.Time { return time.Date(2026, 10, n, 3, 0, 0, 0, time.UTC) }
	f := func(id, title, detail string) checks.Finding {
		return checks.Finding{CheckID: id, Title: title, Detail: detail}
	}
	snap := func(n int, skipped []string, fs ...checks.Finding) store.HostSnapshot {
		h := store.HostSnapshot{Host: "web01", Time: day(n), Findings: fs}
		for _, id := range skipped {
			h.Skipped = append(h.Skipped, scan.Skip{CheckID: id, Reason: "needs root"})
		}
		return h
	}
	sudo := f("ACC-002", "Passwordless sudo rule", "/etc/sudoers.d/deploy: deploy ALL=(ALL) NOPASSWD: /bin/systemctl")
	key1 := f("ACC-006", "SSH key for root has not logged in for 90 days", "SHA256:a in /root/.ssh/authorized_keys; last login 2026-05-02, 150 days ago")
	key1later := f("ACC-006", "SSH key for root has not logged in for 90 days", "SHA256:a in /root/.ssh/authorized_keys; last login 2026-05-02, 155 days ago")
	key2 := f("ACC-006", "SSH key for root has not logged in for 90 days", "SHA256:b in /root/.ssh/authorized_keys; no login since 2026-06-01")

	var open map[openKey]time.Time
	steps := []struct {
		h    store.HostSnapshot
		want map[checks.Finding]time.Time
	}{
		// Day 1: two findings open.
		{snap(1, nil, sudo, f("UPD-001", "3 pending security update(s)", "apt: libssl3, openssl, curl"), key1),
			map[checks.Finding]time.Time{sudo: day(1), key1: day(1)}},
		// Day 2: more updates, a different list, and the key's day count
		// moved on: still the same findings. A second stale key is new.
		{snap(2, nil, sudo, f("UPD-001", "5 pending security update(s)", "apt: libssl3, openssl, curl, git, vim"), key1later, key2),
			map[checks.Finding]time.Time{f("UPD-001", "5 pending security update(s)", "apt: libssl3, openssl, curl, git, vim"): day(1), key1later: day(1), key2: day(2)}},
		// Day 3: scanned without root, so ACC-002 and ACC-006 were skipped:
		// they stay open. UPD-001 ran and is gone.
		{snap(3, []string{"ACC-002", "ACC-006"}),
			map[checks.Finding]time.Time{sudo: day(1), key2: day(2)}},
		// Day 4: back with root; the sudo rule was fixed, then returns on
		// day 5 as a new finding.
		{snap(4, nil, key1later, key2), map[checks.Finding]time.Time{key2: day(2), key1later: day(1)}},
		{snap(5, nil, sudo, key2), map[checks.Finding]time.Time{sudo: day(5), key2: day(2)}},
	}
	for i, s := range steps {
		open = carryOpen(open, s.h)
		for fd, want := range s.want {
			if got, ok := open[keyOf(fd)]; !ok || !got.Equal(want) {
				t.Errorf("step %d, %s %q: opened %v (%v), want %v", i+1, fd.CheckID, fd.Title, got, ok, want)
			}
		}
	}
	if _, ok := open[keyOf(key1)]; ok {
		t.Error("key1 was gone on day 5 (ACC-006 ran) but is still open")
	}
}

func TestOpenSincePages(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "scans")
	day := func(n int) time.Time { return time.Date(2026, 10, n, 3, 0, 0, 0, time.UTC) }
	facts := &collect.Facts{IsRoot: true}
	old := checks.Finding{CheckID: "SSH-002", Severity: checks.Medium, Title: "SSH password authentication is enabled"}
	mid := checks.Finding{CheckID: "UPD-002", Severity: checks.Medium, Title: "Reboot required"}
	fresh := checks.Finding{CheckID: "ACC-002", Severity: checks.High, Title: "Passwordless sudo rule", Detail: "/etc/sudoers.d/x"}
	for _, s := range []struct {
		n  int
		fs []checks.Finding
		e  string
	}{
		{1, []checks.Finding{old}, ""},
		{5, []checks.Finding{old, mid}, ""},
		{6, nil, "connection refused"}, // a failed scan says nothing
		{8, []checks.Finding{old, mid, fresh}, ""},
	} {
		r := scan.HostResult{Host: "web01", Facts: facts, Findings: s.fs, Error: s.e}
		if s.e != "" {
			r.Facts = nil
		}
		if _, err := store.Save(dir, []scan.HostResult{r}, day(s.n)); err != nil {
			t.Fatal(err)
		}
	}
	ix, err := buildIndex(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := day(8).Add(6 * time.Hour)
	want := map[string]string{
		"SSH-002": "open since 2026-10-01 or earlier (7 days)",
		"UPD-002": "open since 2026-10-05 (3 days)",
		"ACC-002": "new in this scan",
	}
	for _, f := range []checks.Finding{old, mid, fresh} {
		if got := ix.withOpen("web01", f, now); got.Open != want[f.CheckID] || got.New != (f.CheckID == "ACC-002") {
			t.Errorf("%s: %q (new %v), want %q", f.CheckID, got.Open, got.New, want[f.CheckID])
		}
	}

	// A host scanned once shows no dates.
	one := filepath.Join(t.TempDir(), "scans")
	store.Save(one, []scan.HostResult{{Host: "db01", Facts: facts, Findings: []checks.Finding{old}}}, day(8))
	ix1, _ := buildIndex(one)
	if got := ix1.withOpen("db01", old, now); got.Open != "" {
		t.Errorf("single scan: %q", got.Open)
	}
}
