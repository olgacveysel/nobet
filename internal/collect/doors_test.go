package collect

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func doorFacts() *Facts {
	return &Facts{
		Passwd: []PasswdEntry{
			{Name: "root", UID: 0, GID: 0, Shell: "/bin/bash"}, {Name: "bob", UID: 1000, GID: 1000, Shell: "/bin/bash"},
			{Name: "jenkins", UID: 1001, GID: 1001, Shell: "/bin/bash"}, {Name: "carol", UID: 1002, GID: 1002, Shell: "/bin/bash"},
			{Name: "alice", UID: 1003, GID: 1003, Shell: "/bin/bash"}, {Name: "lv", UID: 1004, GID: 1004, Shell: "/bin/bash"},
			{Name: "ia", UID: 1005, GID: 1005, Shell: "/bin/bash"}, {Name: "usr", UID: 1006, GID: 1006, Shell: "/bin/bash"},
		},
		Groups: []GroupEntry{
			{Name: "root", GID: 0}, {Name: "disk", GID: 6, Members: []string{"alice"}}, {Name: "cdrom", GID: 24},
			{Name: "docker", GID: 102, Members: []string{"bob"}}, {Name: "libvirt", GID: 103, Members: []string{"lv", "root"}},
			{Name: "incus-admin", GID: 990, Members: []string{"ia"}}, {Name: "incus", GID: 991, Members: []string{"usr"}},
		},
	}
}

// doorsSample is doorsScript output as Debian 13 with Docker, libvirt and
// Incus prints it (Incus's own unix.socket.user is never listed), plus a
// podman socket in a directory others cannot enter.
const doorsSample = `door|disk|/dev/loop0
door|disk|/dev/sda
door|disk|/dev/sda1
door|disk|/dev/sr0
door|docker|/run/docker.sock
door|incus|/var/lib/incus/unix.socket
door|libvirt|/run/libvirt/libvirt-sock
door|podman|/run/podman/podman.sock
door|systemd|/run/systemd/private
stat|0|0|755|directory|/
stat|0|0|755|directory|/dev
stat|0|6|660|block special file|/dev/loop0
stat|0|6|660|block special file|/dev/sda
stat|0|6|660|block special file|/dev/sda1
stat|0|24|660|block special file|/dev/sr0
stat|0|0|755|directory|/run
stat|0|102|660|socket|/run/docker.sock
stat|0|0|755|directory|/run/libvirt
stat|0|0|777|socket|/run/libvirt/libvirt-sock
stat|0|0|700|directory|/run/podman
stat|0|0|666|socket|/run/podman/podman.sock
stat|0|0|755|directory|/run/systemd
stat|0|0|600|socket|/run/systemd/private
stat|0|0|755|directory|/var
stat|0|0|755|directory|/var/lib
stat|0|0|711|directory|/var/lib/incus
stat|0|990|660|socket|/var/lib/incus/unix.socket
acl|/run/docker.sock|user::rw-
acl|/run/docker.sock|user:1001:rw-
acl|/run/docker.sock|group::rw-
acl|/run/docker.sock|mask::rw-
acl|/run/docker.sock|other::---
@@end
`

func TestParseDoors(t *testing.T) {
	f := doorFacts()
	got := f.parseDoors(doorsSample)
	want := []RootDoor{
		{Path: "/dev/sda", Kind: "disk", Accounts: []string{"alice"}, Group: "disk", More: 2},
		{Path: "/run/docker.sock", Kind: "docker", Accounts: []string{"bob", "jenkins"}, Group: "docker", ACL: []string{"jenkins"}},
		{Path: "/var/lib/incus/unix.socket", Kind: "incus", Accounts: []string{"ia"}, Group: "incus-admin"},
		{Path: "/run/libvirt/libvirt-sock", Kind: "libvirt", Accounts: []string{"lv"}, Group: "libvirt", Polkit: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if f.parseDoors(strings.TrimSuffix(doorsSample, "@@end\n")) != nil {
		t.Error("output without @@end parsed")
	}

	f.RootDoors = got
	routes := f.RootDoorRoutes()
	for acct, how := range map[string]string{"bob": "Docker (docker group)", "jenkins": "Docker (ACL on /run/docker.sock)",
		"alice": "raw disks (disk group)", "lv": "libvirt (libvirt group, polkit)", "ia": "Incus (incus-admin group)"} {
		if !reflect.DeepEqual(routes[acct], []string{how}) {
			t.Errorf("%s: %q, want %q", acct, routes[acct], how)
		}
	}
	if len(routes["usr"])+len(routes["carol"])+len(routes["root"]) > 0 {
		t.Errorf("routes for usr, carol or root: %v", routes)
	}

	// A docker.sock opened to all (chmod 666).
	open := strings.Replace(doorsSample, "stat|0|102|660|socket|/run/docker.sock", "stat|0|102|666|socket|/run/docker.sock", 1)
	for _, d := range f.parseDoors(open) {
		if d.Kind == "docker" && (!d.Everyone || d.Accounts != nil) {
			t.Errorf("666 docker.sock: %+v", d)
		}
	}
	f.RootDoors = f.parseDoors(open)
	if r := f.RootDoorRoutes()["*"]; len(r) != 1 || !strings.Contains(r[0], "open to all") {
		t.Errorf("everyone: %q", r)
	}

	// Old scans without RootDoors go by group names; incus is not one.
	f.RootDoors = nil
	routes = f.RootDoorRoutes()
	if !reflect.DeepEqual(routes["bob"], []string{"docker group"}) || !reflect.DeepEqual(routes["ia"], []string{"incus-admin group"}) || routes["usr"] != nil {
		t.Errorf("fallback: %v", routes)
	}
}

// TestDoorsScript runs the real script against a real socket in place of
// /run/docker.sock.
func TestDoorsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	defer l.Close()
	os.Chmod(sock, 0o660)
	os.Chmod(dir, 0o755)
	os.Chmod(filepath.Dir(dir), 0o755) // t.TempDir's parent is 700
	script := strings.Replace(doorsScript(), "docker=/run/docker.sock", "docker="+sock, 1)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	f := &Facts{
		Passwd: []PasswdEntry{{Name: "me", UID: os.Getuid(), GID: gid}, {Name: "other", UID: 99999, GID: 99999}, {Name: "stranger", UID: 99998, GID: 99998}},
		Groups: []GroupEntry{{Name: "mine", GID: gid, Members: []string{"other"}}},
	}
	doors := f.parseDoors(string(out))
	if doors == nil {
		t.Fatalf("no @@end:\n%s", out)
	}
	var d *RootDoor
	for i := range doors {
		if doors[i].Path == sock {
			d = &doors[i]
		}
	}
	// The directories above a temporary directory may keep others out
	// (a home of mode 700); only check the socket when they do not.
	if d == nil {
		t.Skipf("socket not found (directories above it closed?):\n%s", out)
	}
	if d.Kind != "docker" || d.Everyone || !contains(d.Accounts, "other") || contains(d.Accounts, "stranger") {
		t.Errorf("socket: %+v\n%s", *d, out)
	}
	if os.Getuid() != 0 && !contains(d.Accounts, "me") {
		t.Errorf("owner missing: %+v", *d)
	}
	if !strings.Contains(string(out), "stat|"+strconv.Itoa(os.Getuid())+"|") {
		t.Errorf("no stat line for the socket:\n%s", out)
	}
}
