package queue

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

func TestLifecycle(t *testing.T) {
	dir := t.TempDir()
	r, err := Submit(dir, "alice@example.com", []string{"web01"}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Submit(dir, "bob", nil, t0.Add(time.Second)); !errors.Is(err, ErrBusy) {
		t.Errorf("second request while one waits: %v", err)
	}
	p, err := List(dir)
	if err != nil || len(p) != 1 || p[0].State != Waiting || p[0].User != "alice@example.com" || p[0].Hosts[0] != "web01" {
		t.Fatalf("List = %+v, %v", p, err)
	}

	claimed, err := Claim(dir)
	if err != nil || len(claimed) != 1 || claimed[0].ID != r.ID {
		t.Fatalf("Claim = %+v, %v", claimed, err)
	}
	if p, _ := List(dir); len(p) != 1 || p[0].State != Running {
		t.Errorf("after Claim: %+v", p)
	}
	if again, _ := Claim(dir); len(again) != 0 {
		t.Error("a running request was claimed twice")
	}

	done := Done{Request: claimed[0], Started: t0, Finished: t0.Add(time.Minute), Scanned: []string{"web01"}}
	if err := Finish(dir, []Done{done}); err != nil {
		t.Fatal(err)
	}
	if p, _ := List(dir); len(p) != 0 {
		t.Errorf("after Finish: %+v", p)
	}
	recent, err := Recent(dir, 5)
	if err != nil || len(recent) != 1 || recent[0].ID != r.ID || recent[0].Scanned[0] != "web01" {
		t.Errorf("Recent = %+v, %v", recent, err)
	}
	// The queue is free again.
	if _, err := Submit(dir, "bob", nil, t0.Add(2*time.Minute)); err != nil {
		t.Errorf("after the first finished: %v", err)
	}
}

func TestClaimIgnoresJunk(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"bad.json":     "{not json",
		"renamed.json": `{"id":"something-else"}`,
		".half.tmp":    `{"id":"x"}`,
		"notes.txt":    "hello",
		"huge.json":    `{"id":"huge","hosts":["` + strings.Repeat("a", 100<<10) + `"]}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	claimed, err := Claim(dir)
	if err != nil || len(claimed) != 0 {
		t.Errorf("Claim = %+v, %v", claimed, err)
	}
	for _, name := range []string{"bad.invalid", "renamed.invalid", "huge.invalid", ".half.tmp", "notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRecover(t *testing.T) {
	dir := t.TempDir()
	r, _ := Submit(dir, "alice", nil, t0)
	Claim(dir)
	if err := Recover(dir, time.Hour, t0.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if p, _ := List(dir); len(p) != 1 {
		t.Fatal("a recent running request was recovered")
	}
	Recover(dir, time.Hour, t0.Add(2*time.Hour))
	if p, _ := List(dir); len(p) != 0 {
		t.Errorf("stale request still pending: %+v", p)
	}
	if d, _ := Recent(dir, 1); len(d) != 1 || d[0].ID != r.ID || d[0].Error == "" {
		t.Errorf("Recent = %+v", d)
	}
}

func TestHosts(t *testing.T) {
	if got := Hosts([]Request{{Hosts: []string{"a", "b"}}, {Hosts: []string{"b", "c"}}}); strings.Join(got, ",") != "a,b,c" {
		t.Errorf("got %q", got)
	}
	if got := Hosts([]Request{{Hosts: []string{"a"}}, {}}); got != nil {
		t.Errorf("a request for every host: got %q", got)
	}
}

func TestFinishKeepsRecent(t *testing.T) {
	dir := t.TempDir()
	var all []Done
	for i := 0; i < keepDone+5; i++ {
		at := t0.Add(time.Duration(i) * time.Hour)
		r := Request{ID: newID(at), Time: at}
		os.WriteFile(filepath.Join(dir, r.ID+".running"), []byte(`{}`), 0o600)
		all = append(all, Done{Request: r, Finished: at})
	}
	if err := Finish(dir, all); err != nil {
		t.Fatal(err)
	}
	recent, _ := Recent(dir, 100)
	if len(recent) != keepDone || !recent[0].Finished.Equal(t0.Add(time.Duration(keepDone+4)*time.Hour)) {
		t.Errorf("kept %d, newest %v", len(recent), recent[0].Finished)
	}
}
