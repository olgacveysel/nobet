package collect

import (
	"reflect"
	"strings"
	"testing"
)

func TestLoginJobs(t *testing.T) {
	f := &Facts{
		Passwd: []PasswdEntry{
			{Name: "root", UID: 0, GID: 0, Home: "/root"}, {Name: "deploy", UID: 1000, GID: 1000, Home: "/home/deploy"},
			{Name: "bob", UID: 1001, GID: 1001, Home: "/home/bob"}, {Name: "ops", UID: 1002, GID: 1002, Home: "/home/ops"},
			{Name: "svc", UID: 999, GID: 999, Home: "/"}, {Name: "web", UID: 1003, GID: 1003, Home: "/var/www"},
		},
		Groups: []GroupEntry{{Name: "devs", GID: 2000, Members: []string{"deploy", "bob"}}, {Name: "docker", GID: 102, Members: []string{"svc"}}},
		SudoRights: map[string][]SudoEntry{
			"deploy": {{RunAs: "ALL", Commands: []string{"ALL"}, NoPasswd: true}},
			"ops":    {{RunAs: "root", Commands: []string{"/usr/bin/vim"}}},                   // escapes, password asked
			"web":    {{RunAs: "root", Commands: []string{"/usr/sbin/service nginx reload"}}}, // no root
		},
		SSHD:      map[string][]string{"strictmodes": {"yes"}, "authorizedkeysfile": {".ssh/authorized_keys .ssh/authorized_keys2"}},
		RootDoors: []RootDoor{{Path: "/run/docker.sock", Kind: "docker", Accounts: []string{"svc"}, Group: "docker"}},
	}
	jobs := loginJobs(f)
	var names []string
	for _, j := range jobs {
		names = append(names, j.Source)
	}
	if want := []string{"deploy (sudo)", "ops (sudo)", "root (UID 0)"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("jobs %q, want %q (svc has home /, web no root)", names, want)
	}
	if !reflect.DeepEqual(jobs[2].Paths, []string{"/root/.ssh/rc"}) {
		t.Errorf("root: %q", jobs[2].Paths)
	}
	if p := jobs[0].Paths; p[0] != "/home/deploy" || !contains(p, "/home/deploy/.bashrc") || !contains(p, "/home/deploy/.ssh/rc") || contains(p, "/home/deploy/.ssh/authorized_keys") {
		t.Errorf("deploy, StrictModes yes: %q", p)
	}
	f.SSHD["strictmodes"] = []string{"no"}
	if p := loginJobs(f)[0].Paths; !contains(p, "/home/deploy/.ssh/authorized_keys") || !contains(p, "/home/deploy/.ssh/authorized_keys2") {
		t.Errorf("deploy, StrictModes no: %q", p)
	}

	// deploy's home is group-writable for devs (2775): bob is reported once,
	// for the home, and deploy itself never.
	f.SSHD["strictmodes"] = []string{"yes"}
	f.RootJobs = loginJobs(f)
	f.Paths = map[string]PathEntry{
		"/": {Mode: 0o755, Type: "dir"}, "/home": {Mode: 0o755, Type: "dir"}, "/root": {Mode: 0o700, Type: "dir"},
		"/home/deploy":         {UID: 1000, GID: 2000, Mode: 0o2775, Type: "dir"},
		"/home/deploy/.bashrc": {UID: 1000, GID: 1000, Mode: 0o644, Type: "file"},
		"/home/deploy/.ssh":    {UID: 1000, GID: 1000, Mode: 0o700, Type: "dir"},
		"/home/ops":            {UID: 1002, GID: 1002, Mode: 0o700, Type: "dir"},
		"/home/ops/.bashrc":    {UID: 1002, GID: 1002, Mode: 0o644, Type: "file"},
	}
	got := f.writablePaths()
	if len(got) != 1 || got[0].Path != "/home/deploy" || len(got[0].Writers) != 1 || got[0].Writers[0].Account != "bob" {
		t.Fatalf("writable: %+v", got)
	}
	if u := got[0].Use(); !strings.Contains(u, "logins of deploy (sudo), which can become root") {
		t.Errorf("use: %q", u)
	}
	// A world-writable .bashrc in a closed home is its own entry.
	f.Paths["/home/deploy"] = PathEntry{UID: 1000, GID: 1000, Mode: 0o755, Type: "dir"}
	f.Paths["/home/deploy/.bashrc"] = PathEntry{UID: 1000, GID: 1000, Mode: 0o666, Type: "file"}
	if got := f.writablePaths(); len(got) != 1 || got[0].Path != "/home/deploy/.bashrc" || !got[0].Writers[0].Everyone {
		t.Errorf("world-writable .bashrc: %+v", got)
	}
}
