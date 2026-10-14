package collect

import (
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseUpdatesApk(t *testing.T) {
	// updatesScript output on Alpine edge, from real `apk list -u` lines.
	out := `now=1791964400
manager=apk
refreshed=1791964238
refreshed=1791964239
rc=0
upd=apk-tools-3.0.8-r0
upd=busybox-1.38.0-r7
upd=busybox-binsh-1.38.0-r7
upd=busybox-1.38.0-r7
`
	u := parseUpdates(out)
	if !reflect.DeepEqual(u.Pending, []string{"apk-tools", "busybox", "busybox-binsh"}) || u.Err != "" || u.ListsAgeDays != 0 || len(u.Security) != 0 {
		t.Errorf("got %+v", u)
	}

	// Before the first `apk update`: warnings, exit 0, nothing listed.
	if u := parseUpdates("now=1791964400\nmanager=apk\nrc=0\nnocache=1\nnocache=1\n"); u.Err == "" || u.ListsAgeDays != -1 {
		t.Errorf("missing apk cache should set Err: %+v", u)
	}
	if u := parseUpdates("now=1791964400\nmanager=apk\nrc=0\n"); u.Total != 0 || u.Err != "" {
		t.Errorf("no updates: %+v", u)
	}
}

// TestZypperScript runs the real zypper awk filter over list-patches output
// captured on openSUSE Leap 15.6 with an outdated libxml2.
func TestZypperScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	const listPatches = `Repository                                                   | Name                        | Category | Severity  | Interactive | Status | Since      | Summary
-------------------------------------------------------------+-----------------------------+----------+-----------+-------------+--------+------------+----------------------------
Update repository with updates from SUSE Linux Enterprise 15 | openSUSE-SLE-15.6-2024-2290 | security | low       | ---         | needed | 2026-10-14 | Security update for libxml2
Update repository with updates from SUSE Linux Enterprise 15 | openSUSE-SLE-15.6-2025-348  | security | important | ---         | needed | 2026-10-14 | Security update for libxml2
Update repository with updates from SUSE Linux Enterprise 15 | openSUSE-SLE-15.6-2025-901  | security | important | ---         | needed | 2026-10-14 | Security update for the Linux Kernel
Update repository with updates from SUSE Linux Enterprise 15 | openSUSE-SLE-15.6-2025-77   | security | moderate  | ---         | applied| 2026-10-14 | Security update for curl
`
	// The awk program between "awk -F'|' '" and the closing quote.
	start := strings.Index(updatesScript, "awk -F'|' '") + len("awk -F'|' '")
	prog := updatesScript[start : start+strings.Index(updatesScript[start:], "'\n")]
	cmd := exec.Command("awk", "-F|", prog)
	cmd.Stdin = strings.NewReader(listPatches)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	u := parseUpdates("manager=zypper\nrc=0\nrefreshed=1\n" + string(out))
	// libxml2 has a low and an important patch: the worst one counts.
	want := []SecurityUpdate{{Package: "libxml2", Severity: "important"}, {Package: "Linux Kernel", Severity: "important"}}
	if !reflect.DeepEqual(u.Security, want) {
		t.Errorf("got %+v\nawk output:\n%s", u.Security, out)
	}
}

func TestParseUpdatesWorstSeverity(t *testing.T) {
	u := parseUpdates("manager=dnf\nrc=0\nsec=Moderate/Sec. less-590-4.el9.x86_64\nsec=Important/Sec. less-590-5.el9.x86_64\nsec=Low/Sec. less-590-6.el9.x86_64\n")
	if len(u.Security) != 1 || u.Security[0].Severity != "important" {
		t.Errorf("got %+v", u.Security)
	}
}

func TestParseUpdatesStaleness(t *testing.T) {
	// zypper without any repository cache lists nothing and exits 0.
	if u := parseUpdates("now=1791964400\nmanager=zypper\nnocache=1\nrc=0\n"); u.Err == "" {
		t.Errorf("zypper without cache: %+v", u)
	}
	// The newest index file counts: ten days for the oldest repository,
	// two for the newest.
	out := "now=1791964400\nmanager=dnf\nrefreshed=1791100400\nrefreshed=1791791600\nrc=0\n"
	if u := parseUpdates(out); u.ListsAgeDays != 2 {
		t.Errorf("ListsAgeDays = %d, want 2", u.ListsAgeDays)
	}
}

func TestZypperExitCodes(t *testing.T) {
	for rc, wantErr := range map[string]bool{"0": false, "100": false, "101": false, "102": false, "103": false, "104": true, "105": true, "106": true, "1": true} {
		u := parseUpdates("manager=zypper\nrefreshed=1\nrc=" + rc + "\n")
		if (u.Err != "") != wantErr {
			t.Errorf("rc %s: Err %q, want error %v", rc, u.Err, wantErr)
		}
	}
}
