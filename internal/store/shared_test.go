package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/checks"
	"github.com/olgacveysel/nobet/internal/scan"
)

func TestDirFromEnv(t *testing.T) {
	t.Setenv("NOBET_DATA_DIR", "/var/lib/nobet")
	if d, err := Dir(); err != nil || d != filepath.Join("/var/lib/nobet", "scans") {
		t.Errorf("Dir() = %q, %v", d, err)
	}
	t.Setenv("NOBET_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	if d, _ := Dir(); d != filepath.Join("/xdg", "nobet", "scans") {
		t.Errorf("Dir() = %q", d)
	}
}

func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permissions")
	}
	private := filepath.Join(t.TempDir(), "scans")
	p, err := Save(private, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(private); st.Mode().Perm() != 0o700 {
		t.Errorf("new dir mode %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("private file mode %v", st.Mode().Perm())
	}

	// An admin prepared a group-readable shared directory.
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o750); err != nil {
		t.Fatal(err)
	}
	p, err = Save(shared, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
		t.Errorf("shared file mode %v", st.Mode().Perm())
	}
}

func TestSnapshotKeepsAllowlistAndSkips(t *testing.T) {
	r := scan.HostResult{
		Host:       "web01",
		Findings:   []checks.Finding{{CheckID: "SSH-001", Title: "Root can log in"}},
		Suppressed: []scan.Suppressed{{Finding: checks.Finding{CheckID: "NET-001", Title: "tcp/443"}, Reason: "public web", Rule: "allowlist:3"}},
		Skipped:    []scan.Skip{{CheckID: "FS-001", Reason: "needs root"}},
	}
	h := FromResult(r, time.Now())
	if len(h.Findings) != 2 || len(h.Allowlisted) != 1 || len(h.Skipped) != 1 {
		t.Fatalf("snapshot: %+v", h)
	}
	if a := h.Active(); len(a) != 1 || a[0].CheckID != "SSH-001" {
		t.Errorf("Active() = %+v", a)
	}
	// Snapshots from before allowlist decisions were saved: all active.
	h.Allowlisted = nil
	if len(h.Active()) != 2 {
		t.Error("old snapshots should treat every finding as active")
	}
}
