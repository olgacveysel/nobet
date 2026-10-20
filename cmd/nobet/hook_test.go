package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/olgacveysel/nobet/internal/drift"
)

func TestRunHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	out := filepath.Join(t.TempDir(), "hook")
	drifts := []drift.HostDrift{
		{Host: "web01", To: time.Date(2026, 10, 20, 3, 15, 0, 0, time.UTC), Changes: []drift.Change{
			{Kind: drift.Added, Area: "key", What: "deploy: SHA256:abc intruder@x"},
			{Kind: drift.Added, Area: "root", What: "deploy via sudo ALL, no password"},
		}},
		{Host: "db01", Changes: nil}, // unchanged hosts are left out
	}
	runHook(`cat > "$OUT"; echo "$NOBET_CHANGES $NOBET_CHANGED_HOSTS" >> "$OUT.env"; printf '%s' "$NOBET_SUMMARY" > "$OUT.txt"; printf '%s' "$NOBET_SUMMARY_JSON" > "$OUT.json"`, withEnv(t, "OUT", out, drifts))

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got []drift.HostDrift
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("stdin is not JSON: %v\n%s", err, data)
	}
	if len(got) != 1 || got[0].Host != "web01" || len(got[0].Changes) != 2 {
		t.Errorf("got %+v", got)
	}
	env, _ := os.ReadFile(out + ".env")
	if strings.TrimSpace(string(env)) != "2 1" {
		t.Errorf("counts = %q, want \"2 1\"", env)
	}

	wantText := "nöbet: 2 change(s) on 1 host(s)\nweb01: added key: deploy: SHA256:abc intruder@x\nweb01: added root: deploy via sudo ALL, no password"
	if txt, _ := os.ReadFile(out + ".txt"); string(txt) != wantText {
		t.Errorf("NOBET_SUMMARY = %q", txt)
	}
	var fromJSON string
	if js, _ := os.ReadFile(out + ".json"); json.Unmarshal(js, &fromJSON) != nil || fromJSON != wantText {
		t.Errorf("NOBET_SUMMARY_JSON = %q", js)
	}

	// A failing hook is reported, not fatal.
	runHook("exit 3", drifts)
}

func TestHookSummaryCapped(t *testing.T) {
	var cs []drift.Change
	for i := 0; i < 25; i++ {
		cs = append(cs, drift.Change{Kind: drift.Added, Area: "account", What: "u"})
	}
	s := hookSummary([]drift.HostDrift{{Host: "h", Changes: cs}}, 25, 1)
	if lines := strings.Split(s, "\n"); len(lines) != 22 || lines[21] != "(and 5 more; run nobet diff)" {
		t.Errorf("got %d lines, last %q", len(lines), lines[len(lines)-1])
	}
}

// withEnv sets an environment variable for the hook to use.
func withEnv(t *testing.T, k, v string, d []drift.HostDrift) []drift.HostDrift {
	t.Setenv(k, v)
	return d
}
