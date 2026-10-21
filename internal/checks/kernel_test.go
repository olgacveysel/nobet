package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestKernelHardening(t *testing.T) {
	good := func() map[string]string {
		return map[string]string{
			"kernel.randomize_va_space": "2", "fs.protected_symlinks": "1", "fs.protected_hardlinks": "1",
			"fs.suid_dumpable": "2", "net.ipv4.tcp_syncookies": "1", "net.ipv4.conf.all.accept_source_route": "0",
		}
	}
	// Ubuntu's defaults, including suid_dumpable = 2 for apport: nothing to report.
	if got, skip := kernelHardening.Run(&collect.Facts{IsRoot: true, Sysctl: good()}); len(got) != 0 || skip != "" {
		t.Errorf("defaults: %+v %q", got, skip)
	}

	weak := good()
	weak["kernel.randomize_va_space"] = "0"
	weak["net.ipv4.tcp_syncookies"] = "0"
	got, _ := kernelHardening.Run(&collect.Facts{IsRoot: true, Sysctl: weak})
	if len(got) != 1 || got[0].Severity != Medium ||
		!strings.Contains(got[0].Detail, "kernel.randomize_va_space = 0 (want 2)") || !strings.Contains(got[0].Detail, "net.ipv4.tcp_syncookies = 0") {
		t.Errorf("weakened: %+v", got)
	}
	low := good()
	low["net.ipv4.conf.all.accept_source_route"] = "1"
	if got, _ := kernelHardening.Run(&collect.Facts{IsRoot: true, Sysctl: low}); len(got) != 1 || got[0].Severity != Low {
		t.Errorf("source routing only: %+v", got)
	}
	dump := good()
	dump["fs.suid_dumpable"] = "1"
	if got, _ := kernelHardening.Run(&collect.Facts{IsRoot: true, Sysctl: dump}); len(got) != 1 || !strings.Contains(got[0].Detail, "core dumps") {
		t.Errorf("suid_dumpable 1: %+v", got)
	}

	// Without root, fs.protected_* cannot be read: no verdict on them.
	partial := good()
	delete(partial, "fs.protected_symlinks")
	delete(partial, "fs.protected_hardlinks")
	if got, skip := kernelHardening.Run(&collect.Facts{Sysctl: partial}); len(got) != 0 || !strings.Contains(skip, "fs.protected_symlinks, fs.protected_hardlinks (needs root") {
		t.Errorf("unprivileged: %+v %q", got, skip)
	}
	// A weakened value still shows without root.
	partial["kernel.randomize_va_space"] = "1"
	if got, _ := kernelHardening.Run(&collect.Facts{Sysctl: partial}); len(got) != 1 {
		t.Errorf("unprivileged, weakened: %+v", got)
	}
	if _, skip := kernelHardening.Run(&collect.Facts{Errors: map[string]string{"sysctl": "timeout"}}); !strings.Contains(skip, "timeout") {
		t.Errorf("not collected: %q", skip)
	}
}
