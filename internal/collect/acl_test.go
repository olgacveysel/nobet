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

// getfaclSample is `getfacl -s -p -n` output from acl 2.3 (Debian 13; Alma 9
// and Alpine 3.22 print the same), for a lab with ACLs on directories and a
// key, and a directory with a space in its name, an entry the mask limits
// and default entries.
const getfaclSample = `# file: /opt/tool
# owner: 0
# group: 0
user::rwx
user:1002:rwx
group::r-x
mask::rwx
other::r-x

# file: /opt/masked
# owner: 0
# group: 1000
user::rwx
group::r-x
group:1001:rwx
mask::rwx
other::r-x

# file: /home/alice/.ssh/id_ed25519
# owner: 1000
# group: 1001
user::rw-
user:1001:r--
group::---
mask::r--
other::---

# file: /srv/my files
# owner: 0
# group: 0
user::rwx
user:1003:rwx	#effective:r-x
group::r-x
mask::r-x
other::r-x
default:user::rwx
default:user:1003:rwx
default:group::r-x
default:mask::rwx
default:other::r-x

`

// The acls function runs for real, with a getfacl that prints the sample.
func TestACLsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "sample"), []byte(getfaclSample), 0o644)
	os.WriteFile(filepath.Join(dir, "getfacl"), []byte("#!/bin/sh\ncat "+filepath.Join(dir, "sample")+"\n"), 0o755)
	cmd := exec.Command("/bin/sh", "-c", aclsFn+"printf '/opt/tool\\n/srv/my files\\n' | acls; echo @@end")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(l, "acl|") {
			lines = append(lines, l)
		}
	}
	got := parseACLs(lines)
	want := map[string]*ACL{
		"/opt/tool":                   {Group: 5, Users: map[int]uint32{1002: 7}, Groups: map[int]uint32{}},
		"/opt/masked":                 {Group: 5, Users: map[int]uint32{}, Groups: map[int]uint32{1001: 7}},
		"/home/alice/.ssh/id_ed25519": {Group: 0, Users: map[int]uint32{1001: 4}, Groups: map[int]uint32{}},
		"/srv/my files":               {Group: 5, Users: map[int]uint32{1003: 5}, Groups: map[int]uint32{}}, // the mask limits both; defaults do not count
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got:")
		for p, a := range got {
			t.Errorf("  %q: %+v", p, *a)
		}
		t.Errorf("output:\n%s", out)
	}

	// Without getfacl: nothing, and the input is still read.
	cmd = exec.Command("/bin/sh", "-c", aclsFn+"printf '/opt/tool\\n' | acls; echo @@end")
	cmd.Env = append(os.Environ(), "PATH="+t.TempDir())
	if out, err := cmd.Output(); err != nil || string(out) != "@@end\n" {
		t.Errorf("without getfacl: %q, %v", out, err)
	}
}

func TestAccess(t *testing.T) {
	in := func(gids ...int) map[int]bool {
		m := map[int]bool{}
		for _, g := range gids {
			m[g] = true
		}
		return m
	}
	tool := PathEntry{UID: 0, GID: 0, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 5, Users: map[int]uint32{1002: 7}}}
	masked := PathEntry{UID: 0, GID: 1000, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 5, Groups: map[int]uint32{1001: 7}}}
	deny := PathEntry{UID: 0, GID: 1000, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 7, Users: map[int]uint32{1001: 5}}}
	plain := PathEntry{UID: 1000, GID: 1000, Mode: 0o640, Type: "file"}
	cases := []struct {
		name string
		e    PathEntry
		uid  int
		gids map[int]bool
		want uint32
		via  string
	}{
		{"named user writes", tool, 1002, in(1002), 2, viaACLUser},
		{"others read", tool, 1005, in(1005), 4, viaOther},
		{"others cannot write", tool, 1005, in(1005), 2, ""},
		{"the mask's group:: entry, not the mode, decides for the group", masked, 1003, in(1003, 1000), 2, ""},
		{"a named group writes", masked, 1000, in(1000, 1001), 2, viaACLGroup},
		{"a named user entry beats the group", deny, 1001, in(1001, 1000), 2, ""},
		{"the group writes", deny, 1003, in(1003, 1000), 2, viaGroup},
		{"owner", plain, 1000, in(1000), 6, viaOwner},
		{"group reads", plain, 1001, in(1001, 1000), 4, viaGroup},
		{"a matching group that refuses ends it, despite others' bits", PathEntry{UID: 0, GID: 50, Mode: 0o604}, 7, in(50), 4, ""},
	}
	for _, c := range cases {
		if via, _ := c.e.access(c.uid, c.gids, c.want); via != c.via {
			t.Errorf("%s: got %q, want %q", c.name, via, c.via)
		}
	}
}
