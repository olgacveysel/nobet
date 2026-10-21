// Package queue passes scan requests from nobet-web to the scanner without
// giving the dashboard any way to scan: nobet-web only writes a small
// request file, and `nobet scan -queue DIR`, running as the scanner account
// that holds the SSH key, picks it up, scans the hosts it names that are in
// its own inventory, and records the outcome.
//
// A request is <id>.json while it waits and <id>.running while it is being
// scanned; the outcome is <id>.done. The directory is shared: in a systemd
// setup it is /var/lib/nobet/queue, owned by the scanner account with the
// nobet group (mode 2770), which nobet-web belongs to.
package queue

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Request is one ask for a scan.
type Request struct {
	ID    string    `json:"id"`
	Time  time.Time `json:"time"`
	User  string    `json:"user,omitempty"`  // who asked, as nobet-web knows them
	Hosts []string  `json:"hosts,omitempty"` // empty: every host in the scanner's inventory
}

// State of a request.
const (
	Waiting = "waiting"
	Running = "running"
)

// Pending is a request that has not finished.
type Pending struct {
	Request
	State string `json:"state"` // Waiting or Running
}

// Done is the outcome of a request.
type Done struct {
	Request
	Started     time.Time `json:"started"`
	Finished    time.Time `json:"finished"`
	Scanned     []string  `json:"scanned"`               // hosts scanned
	Unreachable []string  `json:"unreachable,omitempty"` // of those, the ones that could not be scanned
	Ignored     []string  `json:"ignored,omitempty"`     // asked for, but not in the scanner's inventory
	Error       string    `json:"error,omitempty"`
}

// maxRequestSize bounds what the scanner reads from the shared directory.
const maxRequestSize = 64 << 10

// keepDone is how many outcomes are kept.
const keepDone = 20

func newID(t time.Time) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// Sortable by time, unique, and safe as a file name.
	return fmt.Sprintf("%d-%s", t.UTC().UnixNano(), hex.EncodeToString(b))
}

// Submit writes a request. It refuses while another one is waiting or
// running, so the queue cannot pile up.
func Submit(dir, user string, hosts []string, now time.Time) (Request, error) {
	pending, err := List(dir)
	if err != nil {
		return Request{}, err
	}
	if len(pending) > 0 {
		return Request{}, ErrBusy
	}
	r := Request{ID: newID(now), Time: now.UTC(), User: user, Hosts: hosts}
	data, err := json.Marshal(r)
	if err != nil {
		return Request{}, err
	}
	// Write to a temporary name first: the scanner only picks up whole files.
	tmp := filepath.Join(dir, "."+r.ID+".tmp")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return Request{}, err
	}
	if err := os.Rename(tmp, filepath.Join(dir, r.ID+".json")); err != nil {
		os.Remove(tmp)
		return Request{}, err
	}
	return r, nil
}

// ErrBusy means a request is already waiting or running.
var ErrBusy = errors.New("a scan is already queued or running")

// List returns the waiting and running requests, oldest first.
func List(dir string) ([]Pending, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Pending
	for _, e := range entries {
		state := ""
		switch {
		case strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), "."):
			state = Waiting
		case strings.HasSuffix(e.Name(), ".running"):
			state = Running
		default:
			continue
		}
		var r Request
		if err := readJSON(filepath.Join(dir, e.Name()), &r); err != nil {
			continue // not ours, or half-written
		}
		out = append(out, Pending{Request: r, State: state})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Claim marks every waiting request as running and returns them, oldest
// first. Files that are not valid requests are moved aside as .invalid.
func Claim(dir string) ([]Request, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Request
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") || !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(dir, name)
		var r Request
		if err := readJSON(p, &r); err != nil || r.ID+".json" != name {
			os.Rename(p, strings.TrimSuffix(p, ".json")+".invalid")
			continue
		}
		if err := os.Rename(p, filepath.Join(dir, r.ID+".running")); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Finish records the outcome of claimed requests and drops old outcomes.
func Finish(dir string, results []Done) error {
	var firstErr error
	for _, d := range results {
		data, err := json.Marshal(d)
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, d.ID+".done"), data, 0o640)
		}
		if err == nil {
			err = os.Remove(filepath.Join(dir, d.ID+".running"))
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	recent, err := Recent(dir, 1<<30)
	if err == nil && len(recent) > keepDone {
		for _, d := range recent[keepDone:] {
			os.Remove(filepath.Join(dir, d.ID+".done"))
		}
	}
	return firstErr
}

// Recover closes requests that have been running for longer than maxAge
// (the scanner was stopped or crashed), so they do not block the queue.
func Recover(dir string, maxAge time.Duration, now time.Time) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var stale []Done
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".running") {
			continue
		}
		var r Request
		if readJSON(filepath.Join(dir, e.Name()), &r) != nil || r.ID+".running" != e.Name() {
			continue
		}
		if now.Sub(r.Time) > maxAge {
			stale = append(stale, Done{Request: r, Finished: now.UTC(), Error: "the scan did not finish (the scanner stopped)"})
		}
	}
	return Finish(dir, stale)
}

// Hosts returns the hosts a set of requests asks for, or nil when any of
// them asks for every host.
func Hosts(reqs []Request) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reqs {
		if len(r.Hosts) == 0 {
			return nil
		}
		for _, h := range r.Hosts {
			if !seen[h] {
				seen[h] = true
				out = append(out, h)
			}
		}
	}
	return out
}

// Recent returns up to n outcomes, newest first.
func Recent(dir string, n int) ([]Done, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Done
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".done") {
			continue
		}
		var d Done
		if readJSON(filepath.Join(dir, e.Name()), &d) == nil {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > n {
		out = out[:n]
	}
	return out, nil
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// A truncated oversized file fails to parse, so it cannot fill memory.
	return json.NewDecoder(io.LimitReader(f, maxRequestSize)).Decode(v)
}
