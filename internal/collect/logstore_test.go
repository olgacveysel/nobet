package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLogStoreScript(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs /proc")
	}
	dir := t.TempDir()
	disk, mem := filepath.Join(dir, "var/log/journal/0123"), filepath.Join(dir, "run/log/journal/0123")
	// A machine-id written after the root file system was created, as on a
	// cloud VM's first boot, so it counts. An hour ahead, because a fresh
	// container's file system can be seconds old.
	machineID := filepath.Join(dir, "machine-id")
	os.WriteFile(machineID, []byte("0123\n"), 0o444)
	firstBoot := time.Now().Add(time.Hour).Truncate(time.Second)
	os.Chtimes(machineID, firstBoot, firstBoot)
	run := func() *LogStore {
		t.Helper()
		script := strings.NewReplacer("/var/log/journal/", dir+"/var/log/journal/", "/run/log/journal/", dir+"/run/log/journal/",
			"/etc/machine-id", machineID).Replace(logStoreScript)
		// A journalctl to find, whether the host has one or not, and an rpm
		// without basesystem.
		os.MkdirAll(dir+"/bin", 0o755)
		os.WriteFile(dir+"/bin/journalctl", []byte("#!/bin/sh\n"), 0o755)
		os.WriteFile(dir+"/bin/rpm", []byte("#!/bin/sh\necho 'package basesystem is not installed'\nexit 1\n"), 0o755)
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+dir+"/bin:"+os.Getenv("PATH"))
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		ls := parseLogStore(string(out))
		if ls == nil {
			t.Fatalf("parse failed:\n%s", out)
		}
		return ls
	}
	if ls := run(); ls.Journal != "unknown" {
		t.Errorf("no journal files: %+v", ls)
	}
	os.MkdirAll(mem, 0o755)
	os.WriteFile(mem+"/system.journal", nil, 0o640)
	if ls := run(); ls.Journal != "volatile" {
		t.Errorf("in memory: %+v", ls)
	}
	os.MkdirAll(disk, 0o755)
	os.WriteFile(disk+"/system@0001-0002.journal", nil, 0o640)
	ls := run()
	if ls.Journal != "persistent" {
		t.Errorf("on disk: %+v", ls)
	}
	// This machine's own boot time; the latest install date wins.
	if ls.Booted.IsZero() || ls.Booted.After(time.Now()) || !ls.Born.Equal(firstBoot) {
		t.Errorf("times: %+v, want born %v", ls, firstBoot)
	}
}

func TestParseLogStore(t *testing.T) {
	got := parseLogStore("journal=volatile\nbooted=1792500000\nborn=1760000000\ndone\n")
	if got == nil || got.Journal != "volatile" || got.Booted.Unix() != 1792500000 || got.Born.Unix() != 1760000000 {
		t.Errorf("got %+v", got)
	}
	// Alpine: no journal, and busybox stat cannot tell the creation time.
	got = parseLogStore("booted=1792500000\nborn=\ndone\n")
	if got == nil || got.Journal != "" || !got.Born.IsZero() {
		t.Errorf("alpine: %+v", got)
	}
	if parseLogStore("journal=persistent\n") != nil {
		t.Error("output without done parsed")
	}
}
