package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestFileCapPermitted(t *testing.T) {
	for _, c := range []struct {
		caps string
		name string
		want bool
	}{
		{"cap_setuid=ep", "cap_setuid", true},
		{"cap_setuid=p", "cap_setuid", true},
		{"cap_setuid=ei", "cap_setuid", false},
		{"cap_setuid+i", "cap_setuid", false},
		{"=ep", "cap_sys_admin", true},
		{"all=p", "cap_chown", true},
		{"= cap_setuid+ep", "cap_setuid", true},   // libcap 2.22
		{"= cap_setuid+ep", "cap_chown", false},   // "=" alone clears
		{"=ep cap_setuid-p", "cap_setuid", false}, // all but one
		{"=ep cap_setuid-p", "cap_chown", true},
		{"cap_net_admin,cap_net_raw+p", "cap_net_raw", true},
		{"cap_net_raw=p cap_dac_override+ep", "cap_dac_override", true},
		{"CAP_SETUID+EP", "cap_setuid", true},
		{"cap_setuid+e-e+p", "cap_setuid", true},
		{"cap_setuid=p-p", "cap_setuid", false},
	} {
		if got := (FileCap{Caps: c.caps}).Permitted(c.name); got != c.want {
			t.Errorf("%q permits %s = %v, want %v", c.caps, c.name, got, c.want)
		}
	}
}

// TestFileCapsScript runs the real script with a stand-in getcap printing
// what libcap 2.75 (-n), 2.48 and 2.22 print.
func TestFileCapsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	root := filepath.Join(dir, "usr")
	for _, f := range []string{"bin/python3.12", "bin/ping", "local/bin/my tool", "local/bin/pyn", "local/bin/plain"} {
		os.MkdirAll(filepath.Dir(filepath.Join(root, f)), 0o755)
		os.WriteFile(filepath.Join(root, f), []byte("x"), 0o755)
	}
	getcap := `#!/bin/sh
[ "$1" = -n ] && shift
[ "$1" = / ] && exit 0
for f; do
  case "$f" in
    */python3.12) echo "$f cap_setuid=ep" ;;
    */ping) echo "$f = cap_net_admin,cap_net_raw+p" ;;
    *"/my tool") echo "$f cap_net_raw=p cap_dac_override+ep" ;;
    */pyn) echo "$f cap_setuid=ep [rootid=1000]" ;;
  esac
done
`
	os.WriteFile(filepath.Join(bin, "getcap"), []byte(getcap), 0o755)
	script := strings.Replace(fileCapsScript, "for d in /bin /sbin /usr /opt /etc /tmp /var/tmp /home /root /srv", "for d in "+root, 1)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got, e := parseFileCaps(string(out))
	if e != "" {
		t.Fatalf("%s\n%s", e, out)
	}
	byPath := map[string]FileCap{}
	for _, c := range got {
		c.Owner = "" // depends on whether dpkg or rpm is installed
		byPath[strings.TrimPrefix(c.Path, root)] = c
	}
	want := map[string]FileCap{
		"/bin/python3.12":    {Path: root + "/bin/python3.12", Caps: "cap_setuid=ep"},
		"/bin/ping":          {Path: root + "/bin/ping", Caps: "= cap_net_admin,cap_net_raw+p"},
		"/local/bin/my tool": {Path: root + "/local/bin/my tool", Caps: "cap_net_raw=p cap_dac_override+ep"},
		"/local/bin/pyn":     {Path: root + "/local/bin/pyn", Caps: "cap_setuid=ep", RootID: 1000},
	}
	if !reflect.DeepEqual(byPath, want) {
		t.Errorf("got  %+v\nwant %+v\noutput:\n%s", byPath, want, out)
	}

	// Without getcap (the script adds /usr/sbin and /sbin to PATH, where a
	// real one may be, so ask for a name nothing has).
	cmd = exec.Command("/bin/sh", "-c", strings.ReplaceAll(script, "command -v getcap", "command -v nobet-no-getcap"))
	if out, _ := cmd.Output(); !strings.Contains(string(out), "nogetcap") {
		t.Errorf("without getcap: %s", out)
	}
	if c, e := parseFileCaps("nogetcap\n"); c != nil || !strings.Contains(e, "getcap is not installed") {
		t.Errorf("nogetcap: %v %q", c, e)
	}
	if c, e := parseFileCaps("cap=pkg|0|cap_setuid=ep|/usr/bin/x\n"); c != nil || e == "" {
		t.Errorf("no @@end: %v %q", c, e)
	}
}
