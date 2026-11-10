package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestRootDoors(t *testing.T) {
	base := func(doors []collect.RootDoor) *collect.Facts {
		return &collect.Facts{
			Passwd: []collect.PasswdEntry{{Name: "root"}, {Name: "bob", UID: 1000}, {Name: "ia", UID: 1001}, {Name: "usr", UID: 1002}},
			Groups: []collect.GroupEntry{{Name: "docker", GID: 102, Members: []string{"bob"}},
				{Name: "incus-admin", GID: 990, Members: []string{"ia"}}, {Name: "incus", GID: 991, Members: []string{"usr"}}},
			Errors:    map[string]string{"doors": "the listing stopped early"},
			RootDoors: doors,
		}
	}
	got, _ := rootGroupMembers.Run(base([]collect.RootDoor{
		{Path: "/run/docker.sock", Kind: "docker", Accounts: []string{"bob", "jenkins"}, Group: "docker", ACL: []string{"jenkins"}},
		{Path: "/run/libvirt/libvirt-sock", Kind: "libvirt", Accounts: []string{"lv"}, Group: "libvirt", Polkit: true},
		{Path: "/run/libvirt/virtqemud-sock", Kind: "libvirt", Accounts: []string{"lv"}, Group: "libvirt", Polkit: true},
		{Path: "/dev/sda", Kind: "disk", Accounts: []string{"alice"}, Readers: []string{"backup"}, Group: "disk", More: 3},
		{Path: "/run/podman/podman.sock", Kind: "podman", Everyone: true},
	}))
	want := []struct {
		sev           Severity
		title, detail string
	}{
		{High, "2 account(s) can control Docker, which is root on the host", "bob (docker group); jenkins (ACL on /run/docker.sock) through /run/docker.sock"},
		{High, "1 account(s) can control libvirt, which is root on the host", "lv (libvirt group, polkit) through /run/libvirt/libvirt-sock, /run/libvirt/virtqemud-sock"},
		{High, "1 account(s) can write raw disks, which is root on the host", "alice (disk group) through /dev/sda and 3 more"},
		{High, "1 account(s) can read raw disks, and with them every file", "backup can read /dev/sda and 3 more"},
		{Critical, "Every account can control podman, which is root on the host", "/run/podman/podman.sock can be opened by every account"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings: %+v", len(got), got)
	}
	for i, w := range want {
		if got[i].Severity != w.sev || got[i].Title != w.title || !strings.HasPrefix(got[i].Detail, w.detail) {
			t.Errorf("finding %d:\n got  %v %q %q\n want %v %q %q", i, got[i].Severity, got[i].Title, got[i].Detail, w.sev, w.title, w.detail)
		}
	}
	// chmod o+r /dev/sda: everyone reads it; o+rw: everyone writes, and
	// only that device is named.
	got, _ = rootGroupMembers.Run(base([]collect.RootDoor{
		{Path: "/dev/sdb", Kind: "disk", Accounts: []string{"alice"}, Group: "disk", More: 27},
		{Path: "/dev/sda", Kind: "disk", ReadAll: true, Accounts: []string{"alice"}, Group: "disk"},
	}))
	if len(got) != 2 || got[1].Title != "Every account can read raw disks, and with them every file" || !strings.HasPrefix(got[1].Detail, "/dev/sda can be read") {
		t.Errorf("disk readable by all: %+v", got)
	}
	got, _ = rootGroupMembers.Run(base([]collect.RootDoor{
		{Path: "/dev/sdb", Kind: "disk", Accounts: []string{"alice"}, Group: "disk", More: 27},
		{Path: "/dev/sda", Kind: "disk", Everyone: true},
	}))
	if len(got) != 1 || got[0].Severity != Critical || got[0].Title != "Every account can write raw disks, which is root on the host" || got[0].Detail != "/dev/sda can be opened by every account" {
		t.Errorf("disk writable by all: %+v", got)
	}
	if got, _ := rootGroupMembers.Run(base([]collect.RootDoor{})); len(got) != 0 {
		t.Errorf("no doors: %+v", got)
	}
	// Without the sockets, group names: incus-admin, not incus.
	got, _ = rootGroupMembers.Run(base(nil))
	if len(got) != 2 || !strings.Contains(got[0].Title, "docker group") || !strings.Contains(got[1].Title, "incus-admin group") ||
		!strings.Contains(got[0].Detail, "stopped early") {
		t.Errorf("fallback: %+v", got)
	}
}
