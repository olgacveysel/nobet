// Package store keeps scan history on disk so later scans can be compared
// with earlier ones. Each scan is one JSON file under
// ~/.local/share/nobet/scans ($XDG_DATA_HOME/nobet/scans, or
// $NOBET_DATA_DIR/scans for a shared history). Files hold sensitive data
// (sudo rules, key fingerprints), so a new directory is 0700 and files are
// 0600. A shared directory that an admin made group-readable gets 0640
// files, so a dashboard running as a group member can read them.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/collect"
	"github.com/olgacveysel/nobet/internal/scan"
)

// FormatVersion is bumped when the snapshot format changes incompatibly.
const FormatVersion = 1

// HostSnapshot is one host's state at scan time.
type HostSnapshot struct {
	Host        string            `json:"host"`
	Time        time.Time         `json:"time"`
	Local       bool              `json:"local,omitempty"`
	Error       string            `json:"error,omitempty"`
	Findings    []checks.Finding  `json:"findings"`              // every finding, allowlisted or not
	Allowlisted []scan.Suppressed `json:"allowlisted,omitempty"` // which of them the allowlist covered at scan time
	Skipped     []scan.Skip       `json:"skipped,omitempty"`
	DurationMS  int64             `json:"duration_ms,omitempty"`
	Facts       *collect.Facts    `json:"facts,omitempty"`
}

// Active returns the findings the allowlist did not cover at scan time.
func (h HostSnapshot) Active() []checks.Finding {
	covered := map[string]bool{}
	for _, s := range h.Allowlisted {
		covered[findingKey(s.Finding)] = true
	}
	out := []checks.Finding{}
	for _, f := range h.Findings {
		if !covered[findingKey(f)] {
			out = append(out, f)
		}
	}
	return out
}

func findingKey(f checks.Finding) string {
	return f.CheckID + "\x00" + f.Title + "\x00" + f.Detail
}

// Snapshot is one saved scan.
type Snapshot struct {
	Version int            `json:"version"`
	Time    time.Time      `json:"time"`
	Hosts   []HostSnapshot `json:"hosts"`
}

// Dir returns the default history directory: $NOBET_DATA_DIR/scans when
// set (a shared history, for example /var/lib/nobet/scans), otherwise the
// user's own.
func Dir() (string, error) {
	if d := os.Getenv("NOBET_DATA_DIR"); d != "" {
		return filepath.Join(d, "scans"), nil
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "nobet", "scans"), nil
}

// FromResult turns a scan result into a snapshot entry. Allowlisted
// findings are included, so editing the allowlist never looks like drift.
func FromResult(r scan.HostResult, t time.Time) HostSnapshot {
	hs := HostSnapshot{Host: r.Host, Time: t, Local: r.Local, Error: r.Error, Facts: r.Facts,
		Allowlisted: r.Suppressed, Skipped: r.Skipped, DurationMS: r.DurationMS}
	hs.Findings = append([]checks.Finding{}, r.Findings...)
	for _, s := range r.Suppressed {
		hs.Findings = append(hs.Findings, s.Finding)
	}
	return hs
}

// Save writes results as a new snapshot and returns its path.
func Save(dir string, results []scan.HostResult, t time.Time) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	snap := Snapshot{Version: FormatVersion, Time: t.UTC()}
	for _, r := range results {
		snap.Hosts = append(snap.Hosts, FromResult(r, snap.Time))
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return "", err
	}
	name := filepath.Join(dir, snap.Time.Format("20060102T150405.000Z")+".json")
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return "", err
	}
	// Set the mode explicitly: WriteFile's is subject to the umask.
	if err := os.Chmod(tmp, fileMode(dir)); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return name, os.Rename(tmp, name)
}

// fileMode is 0640 in a directory an admin made group-readable for a
// shared history, and 0600 otherwise.
func fileMode(dir string) os.FileMode {
	if st, err := os.Stat(dir); err == nil && st.Mode().Perm()&0o040 != 0 {
		return 0o640
	}
	return 0o600
}

// Walk calls fn with each snapshot in dir, oldest first, reading one file
// at a time so that a long history never has to fit in memory. Unreadable
// files are skipped; a missing directory means no history.
func Walk(dir string, fn func(Snapshot) error) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // names are timestamps, so this is chronological
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var s Snapshot
		if json.Unmarshal(data, &s) != nil || s.Version != FormatVersion {
			continue
		}
		if err := fn(s); err != nil {
			return err
		}
	}
	return nil
}

// Recent returns up to n of each host's newest successful scans, oldest
// first, and every host that appears in the history, sorted. It holds no
// more than that in memory.
func Recent(dir string, n int) (map[string][]HostSnapshot, []string, error) {
	recent := map[string][]HostSnapshot{}
	seen := map[string]bool{}
	var hosts []string
	err := Walk(dir, func(s Snapshot) error {
		for _, h := range s.Hosts {
			if !seen[h.Host] {
				seen[h.Host] = true
				hosts = append(hosts, h.Host)
			}
			if h.Error == "" && h.Facts != nil {
				l := append(recent[h.Host], h)
				if len(l) > n {
					l = l[len(l)-n:]
				}
				recent[h.Host] = l
			}
		}
		return nil
	})
	sort.Strings(hosts)
	return recent, hosts, err
}

// Prune deletes all but the newest keep snapshots.
func Prune(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // names are timestamps, so this is chronological
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			return fmt.Errorf("pruning history: %w", err)
		}
		names = names[1:]
	}
	return nil
}
