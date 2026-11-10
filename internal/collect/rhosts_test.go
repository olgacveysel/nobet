package collect

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestRhostsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	put := func(p, content string) {
		t.Helper()
		p = filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(content), 0o644)
	}
	// What the lab used, and what OpenSSH ignores: + wildcards (host or
	// user), negations and comments.
	put("etc/hosts.equiv", "# trusted\n+\n172.31.10.20\nbuild.lan bob\n-badhost\n+@admins\n")
	put("etc/ssh/shosts.equiv", "hb-cli\n")
	put("root/.shosts", "172.31.10.20 root\n")
	put("home/alice/.rhosts", "+ alice\n10.0.0.7 alice # laptop\nlab +\n")
	uid := strconv.Itoa(os.Getuid())
	put("etc/passwd", "root:x:0:0::"+dir+"/root:/bin/sh\nalice:x:"+uid+":"+uid+"::"+dir+"/home/alice:/bin/sh\nbob:x:1001:1001::"+dir+"/home/bob:/bin/sh\n")
	out, err := exec.Command("/bin/sh", "-c", strings.ReplaceAll(rhostsScript, "/etc/", dir+"/etc/")).Output()
	if err != nil {
		t.Fatal(err)
	}
	got := parseRhosts(string(out))
	e, s := dir+"/etc/hosts.equiv", dir+"/etc/ssh/shosts.equiv"
	want := []HostTrust{
		{File: e, Host: "172.31.10.20"}, {File: e, Host: "build.lan", User: "bob"}, {File: e, Host: "+@admins"},
		{File: s, Host: "hb-cli"},
		{File: dir + "/root/.shosts", Account: "root", Host: "172.31.10.20", User: "root"},
		{File: dir + "/home/alice/.rhosts", Account: "alice", Host: "10.0.0.7", User: "alice"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v\noutput:\n%s", got, want, out)
	}
	if parseRhosts(strings.TrimSuffix(string(out), "@@end\n")) != nil {
		t.Error("output without @@end parsed")
	}
}
