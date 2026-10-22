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

func writersFacts() *Facts {
	return &Facts{
		Passwd: []PasswdEntry{
			{Name: "root", UID: 0, GID: 0}, {Name: "deploy", UID: 1000, GID: 1000},
			{Name: "alice", UID: 1001, GID: 1001}, {Name: "bob", UID: 1002, GID: 1002},
		},
		Groups: []GroupEntry{
			{Name: "root", GID: 0}, {Name: "deploy", GID: 1000}, {Name: "alice", GID: 1001},
			{Name: "bob", GID: 1002}, {Name: "ops", GID: 2000, Members: []string{"alice", "root"}},
		},
		Paths: map[string]PathEntry{
			"/":                        {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/opt":                     {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/opt/app":                 {UID: 1000, GID: 1000, Mode: 0o755, Type: "dir"},
			"/opt/app/run.sh":          {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/opt/ops":                 {UID: 0, GID: 2000, Mode: 0o775, Type: "dir"},
			"/opt/ops/sync":            {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/opt/open.sh":             {UID: 0, GID: 0, Mode: 0o757, Type: "file"},
			"/usr":                     {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/usr/bin":                 {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/usr/bin/ok":              {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/usr/bin/odd":             {UID: 4242, GID: 0, Mode: 0o755, Type: "file"},
			"/tmp":                     {UID: 0, GID: 0, Mode: 0o1777, Type: "dir"},
			"/tmp/root-owned.sh":       {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/tmp/bobs.sh":             {UID: 1002, GID: 1002, Mode: 0o755, Type: "file"},
			"/usr/bin/python3":         {UID: 0, GID: 0, Mode: 0o777, Type: "link"},
			"/opt/app/venv":            {UID: 1000, GID: 1000, Mode: 0o755, Type: "dir"},
			"/opt/app/venv/python3.12": {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			// merged /usr: /sbin -> usr/sbin
			"/sbin":                  {UID: 0, GID: 0, Mode: 0o777, Type: "link"},
			"/usr/sbin":              {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/usr/sbin/fsck":         {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/etc":                   {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/etc/cron.daily":        {UID: 0, GID: 0, Mode: 0o755, Type: "dir"},
			"/etc/cron.daily/report": {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			// ACLs: bob named; the ops group masked off (group:: r-x) and
			// deploy's group named; alice's own entry refusing what ops allows.
			"/opt/acl":        {UID: 0, GID: 0, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 5, Users: map[int]uint32{1002: 7}}},
			"/opt/acl/job":    {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/opt/masked":     {UID: 0, GID: 2000, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 5, Groups: map[int]uint32{1000: 7}}},
			"/opt/masked/job": {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
			"/opt/deny":       {UID: 0, GID: 2000, Mode: 0o775, Type: "dir", ACL: &ACL{Group: 7, Users: map[int]uint32{1001: 5}}},
			"/opt/deny/job":   {UID: 0, GID: 0, Mode: 0o755, Type: "file"},
		},
		Links:        map[string]string{"/usr/bin/python3": "/opt/app/venv/python3.12", "/sbin/fsck": "/usr/sbin/fsck"},
		Interpreters: map[string]string{"/etc/cron.daily/report": "/opt/app/venv/python3.12"},
	}
}

func TestWriters(t *testing.T) {
	f := writersFacts()
	cases := map[string][]Writer{
		"/usr/bin/ok":            nil,
		"/opt/app/run.sh":        {{Account: "deploy", Path: "/opt/app", How: "owner"}},    // root's file in deploy's directory
		"/opt/ops/sync":          {{Account: "alice", Path: "/opt/ops", How: "group ops"}}, // root is in ops too, but already root
		"/opt/open.sh":           {{Everyone: true, Path: "/opt/open.sh", How: "world-writable"}},
		"/usr/bin/odd":           {{Account: "uid 4242", Path: "/usr/bin/odd", How: "owner"}},
		"/tmp/root-owned.sh":     nil, // sticky /tmp protects it
		"/tmp/bobs.sh":           {{Account: "bob", Path: "/tmp/bobs.sh", How: "owner"}},
		"/tmp/missing.sh":        {{Everyone: true, Path: "/tmp", How: "world-writable"}},    // anyone can create it
		"/tmp":                   {{Everyone: true, Path: "/tmp", How: "world-writable"}},    // a directory root runs everything in
		"/usr/bin/python3":       {{Account: "deploy", Path: "/opt/app/venv", How: "owner"}}, // through the link's target
		"/sbin/fsck":             nil,                                                        // a symlinked directory's own mode means nothing
		"/etc/cron.daily/report": {{Account: "deploy", Path: "/opt/app/venv", How: "owner", Through: "/opt/app/venv/python3.12"}},
		"/opt/acl/job":           {{Account: "bob", Path: "/opt/acl", How: "an ACL"}},
		"/opt/masked/job":        {{Account: "deploy", Path: "/opt/masked", How: "an ACL for group deploy"}},
		"/opt/deny/job":          nil,
	}
	for p, want := range cases {
		if got := f.Writers(p); !reflect.DeepEqual(got, want) {
			t.Errorf("Writers(%s) = %+v, want %+v", p, got, want)
		}
	}
}

func TestWriterText(t *testing.T) {
	cases := map[string]Writer{
		"deploy owns /opt/app":                                               {Account: "deploy", Path: "/opt/app", How: "owner"},
		"alice through group ops on /opt/ops":                                {Account: "alice", Path: "/opt/ops", How: "group ops"},
		"/tmp is world-writable":                                             {Everyone: true, Path: "/tmp", How: "world-writable"},
		"bob through an ACL on /opt/acl":                                     {Account: "bob", Path: "/opt/acl", How: "an ACL"},
		"deploy owns /opt/venv (above its interpreter /opt/venv/bin/python)": {Account: "deploy", Path: "/opt/venv", How: "owner", Through: "/opt/venv/bin/python"},
		"app owns its interpreter /opt/venv/bin/python":                      {Account: "app", Path: "/opt/venv/bin/python", How: "owner", Through: "/opt/venv/bin/python"},
	}
	for want, w := range cases {
		if got := w.String(); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

func TestWritablePaths(t *testing.T) {
	f := writersFacts()
	f.Calls = map[string][]string{"/usr/bin/ok": {"/opt/open.sh", "/usr/bin/odd"}}
	f.RootJobs = []RootJob{
		{Kind: "cron", Source: "/etc/cron.d/app", Paths: []string{"/usr/bin/ok", "/opt/app/run.sh"}},
		{Kind: "sudo", Source: "sudo rule for alice", Paths: []string{"/opt/ops/sync"}},
		{Kind: "path", Source: "standard directories", Paths: []string{"/usr/bin", "/opt/ops"}},
		{Kind: "path", Source: "/etc/environment", Paths: []string{"/opt/ops"}}, // reported once
	}
	want := []WritablePath{
		{Kind: "cron", Source: "/etc/cron.d/app", Path: "/opt/open.sh", CalledBy: "/usr/bin/ok", Writers: []Writer{{Everyone: true, Path: "/opt/open.sh", How: "world-writable"}}},
		{Kind: "cron", Source: "/etc/cron.d/app", Path: "/usr/bin/odd", CalledBy: "/usr/bin/ok", Writers: []Writer{{Account: "uid 4242", Path: "/usr/bin/odd", How: "owner"}}},
		{Kind: "cron", Source: "/etc/cron.d/app", Path: "/opt/app/run.sh", Writers: []Writer{{Account: "deploy", Path: "/opt/app", How: "owner"}}},
		{Kind: "sudo", Source: "sudo rule for alice", Path: "/opt/ops/sync", Writers: []Writer{{Account: "alice", Path: "/opt/ops", How: "group ops"}}},
		{Kind: "path", Source: "standard directories", Path: "/opt/ops", Writers: []Writer{{Account: "alice", Path: "/opt/ops", How: "group ops"}}},
	}
	if got := f.writablePaths(); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// The stat script runs for real on a directory tree with known modes.
func TestPathsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "app", "bin"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "app", "bin", "run.sh"), []byte("#!/bin/sh\n"), 0o755))
	must(os.Chmod(filepath.Join(dir, "app", "bin", "run.sh"), 0o757))
	must(os.Mkdir(filepath.Join(dir, "drop"), 0o755))
	must(os.Chmod(filepath.Join(dir, "drop"), os.ModeSticky|0o777))
	must(os.Symlink(filepath.Join(dir, "app", "bin", "run.sh"), filepath.Join(dir, "link")))
	must(os.Symlink(filepath.Join(dir, "app"), filepath.Join(dir, "applink"))) // like /sbin -> usr/sbin
	// Scripts whose #! interpreter lives elsewhere, or is found through env.
	must(os.MkdirAll(filepath.Join(dir, "venv", "bin"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "venv", "bin", "python"), []byte("\x7fELF"), 0o755))
	job := filepath.Join(dir, "app", "job.py")
	must(os.WriteFile(job, []byte("#!"+filepath.Join(dir, "venv", "bin", "python")+" -u\r\nprint(1)\n"), 0o755))
	// A script that sources and calls other files by path.
	cronJob := filepath.Join(dir, "app", "cron-job")
	must(os.WriteFile(cronJob, []byte(strings.ReplaceAll(`#!/bin/sh
# not this: /D/ignored
. /D/lib/common.sh
FOO=1 /D/bin/helper --x && echo done > /D/out.log
if [ -x /D/bin/maybe ]; then /D/bin/maybe; fi
bash -e /D/bin/step.sh
python3 -u /D/tool.py
cd /D; ./relative
`, "/D", dir)), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "bin"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "bin", "helper"), []byte("#!/bin/sh\n"), 0o755))
	envJob := filepath.Join(dir, "app", "env-job")
	must(os.WriteFile(envJob, []byte("#!/usr/bin/env -S sh -e\necho hi\n"), 0o755))

	run := filepath.Join(dir, "app", "bin", "run.sh")
	viaDir := filepath.Join(dir, "applink", "bin", "run.sh")
	paths := []string{run, filepath.Join(dir, "drop"), filepath.Join(dir, "link"), filepath.Join(dir, "missing"), viaDir, job, envJob, cronJob}
	out, err := exec.Command("/bin/sh", "-c", pathsScript(paths)).Output()
	if err != nil {
		t.Fatal(err)
	}
	entries, links, interps, calls := parsePaths(string(out))
	if entries == nil {
		t.Fatalf("incomplete output:\n%s", out)
	}
	uid := os.Getuid()
	checks := map[string]PathEntry{
		run:                        {UID: uid, Mode: 0o757, Type: "file"},
		filepath.Join(dir, "drop"): {UID: uid, Mode: 0o1777, Type: "dir"},
		filepath.Join(dir, "link"): {UID: uid, Type: "link"},
		filepath.Join(dir, "app"):  {UID: uid, Mode: 0o755, Type: "dir"},
		"/":                        {UID: 0, Type: "dir"},
	}
	for p, want := range checks {
		got, ok := entries[p]
		if !ok || got.UID != want.UID || got.Type != want.Type || (want.Mode != 0 && got.Mode != want.Mode) {
			t.Errorf("%s: got %+v (found %v), want %+v", p, got, ok, want)
		}
	}
	if _, ok := entries[filepath.Join(dir, "missing")]; ok {
		t.Error("a missing path got an entry")
	}
	if links[filepath.Join(dir, "link")] != run || links[viaDir] != run {
		t.Errorf("links = %v", links)
	}
	if _, ok := links[run]; ok {
		t.Errorf("a path without symlinks got resolved: %v", links)
	}
	if interps[job] != filepath.Join(dir, "venv", "bin", "python") || !strings.HasSuffix(interps[envJob], "/sh") || interps[run] != "/bin/sh" {
		t.Errorf("interpreters = %v", interps)
	}
	if _, ok := entries[filepath.Join(dir, "venv")]; !ok {
		t.Error("the interpreter's directories were not listed")
	}
	var want []string
	for _, p := range []string{"/bin/helper", "/bin/maybe", "/bin/step.sh", "/lib/common.sh", "/tool.py"} {
		want = append(want, dir+p)
	}
	if !reflect.DeepEqual(calls[cronJob], want) {
		t.Errorf("calls = %q\nwant %q", calls[cronJob], want)
	}
	if _, ok := entries[filepath.Join(dir, "bin", "helper")]; !ok {
		t.Error("the called files were not listed")
	}
}

func TestParseRootJobs(t *testing.T) {
	out := strings.Join([]string{
		"@@cron system /etc/cron.d/app",
		"*/10 * * * * root /opt/app/tick.sh",
		"@@cron user /var/spool/cron/crontabs/root",
		"@daily /root/clean.sh",
		"@@files run-parts /etc/cron.daily",
		"/etc/cron.daily",
		"/etc/cron.daily/logrotate",
		"@@files startup root's shell startup files",
		"/etc/profile",
		"/root/.bashrc",
		"@@files config account, sudo and loader configuration",
		"/etc/passwd",
		"/etc/sudoers",
		"@@systemd",
		"Id=app.service",
		"User=",
		"ExecStart={ path=/opt/app/server ; argv[]=/opt/app/server ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
		"",
		"@@end",
	}, "\n")
	got := parseRootJobs(out)
	want := []RootJob{
		{Kind: "cron", Source: "/etc/cron.d/app", Paths: []string{"/etc/cron.d/app", "/opt/app/tick.sh"}},
		{Kind: "cron", Source: "/var/spool/cron/crontabs/root", Paths: []string{"/var/spool/cron/crontabs/root", "/root/clean.sh"}},
		{Kind: "run-parts", Source: "/etc/cron.daily", Paths: []string{"/etc/cron.daily", "/etc/cron.daily/logrotate"}},
		{Kind: "startup", Source: "root's shell startup files", Paths: []string{"/etc/profile", "/root/.bashrc"}},
		{Kind: "config", Source: "account, sudo and loader configuration", Paths: []string{"/etc/passwd", "/etc/sudoers"}},
		{Kind: "systemd", Source: "app.service", Paths: []string{"/opt/app/server"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if parseRootJobs("@@cron user /x\n@daily /y\n") != nil {
		t.Error("output without @@end should count as incomplete")
	}
	if parseRootJobs("@@systemd\n@@failed\n@@end\n") != nil {
		t.Error("a failed systemctl should count as incomplete")
	}
}

func TestUseCalledBy(t *testing.T) {
	w := WritablePath{Kind: "cron", Source: "/etc/cron.d/report", Path: "/opt/lib.sh", CalledBy: "/usr/local/sbin/report"}
	if got := w.Use(); got != "run or sourced by /usr/local/sbin/report, which is used by root's cron (/etc/cron.d/report)" {
		t.Errorf("Use() = %q", got)
	}
}

func TestSecurePathJob(t *testing.T) {
	got := securePathJob([]SudoLine{
		{File: "/etc/sudoers", Text: `Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"`},
		{File: "/etc/sudoers.d/ops", Text: `Defaults    secure_path = /opt/tools/bin:/usr/bin`},
		{File: "/etc/sudoers", Text: `root ALL=(ALL:ALL) ALL`},
	})
	want := []RootJob{{Kind: "path", Source: "sudo's secure_path", Paths: []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin", "/opt/tools/bin"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	if securePathJob(nil) != nil {
		t.Error("no secure_path, no job")
	}
}

func TestRootPathsSafe(t *testing.T) {
	jobs := []RootJob{{Paths: []string{"/opt/ok", "/opt/with space", "/opt/quote'x", "/opt/ok", "/opt/$(id)"}}}
	got, truncated := rootPaths(jobs)
	if !reflect.DeepEqual(got, []string{"/opt/ok"}) || truncated {
		t.Errorf("got %q, %v", got, truncated)
	}
}
