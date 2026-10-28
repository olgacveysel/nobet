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

// The script runs for real on a fake /proc: a dockerd with flags, one with
// its own daemon.json, and another process.
func TestDockerAPIScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	proc := func(pid, comm string, args []string, env ...string) {
		t.Helper()
		p := filepath.Join(dir, "proc", pid)
		os.MkdirAll(p, 0o755)
		os.WriteFile(p+"/comm", []byte(comm+"\n"), 0o644)
		os.WriteFile(p+"/cmdline", []byte(strings.Join(args, "\x00")+"\x00"), 0o644)
		os.WriteFile(p+"/environ", []byte(strings.Join(env, "\x00")+"\x00"), 0o644)
	}
	proc("101", "dockerd", []string{"/usr/bin/dockerd", "-H", "fd://", "-H", "tcp://0.0.0.0:2375", "--containerd=/run/containerd/containerd.sock"},
		"PATH=/usr/bin", "AWS_SECRET_ACCESS_KEY=envsecret")
	proc("102", "dockerd", []string{"/usr/bin/dockerd", "--config-file=" + dir + "/etc/docker/other.json"}, "DOCKER_TLS_VERIFY=1")
	proc("103", "containerd", []string{"/usr/bin/containerd", "-H", "tcp://0.0.0.0:1"})
	os.MkdirAll(dir+"/etc/docker", 0o755)
	os.WriteFile(dir+"/etc/docker/daemon.json", []byte(`{"tls": false}`), 0o644)
	// Pretty-printed, with a proxy password and a syslog address that are
	// not hosts.
	os.WriteFile(dir+"/etc/docker/other.json", []byte(`{
  "hosts": ["unix:///var/run/docker.sock", "tcp://10.0.0.5:2376"],
  "tls": true,
  "tlsverify" : false,
  "proxies": {"http-proxy": "http://user:proxysecret@proxy:3128"},
  "log-opts": {"syslog-address": "tcp://logs:514"}
}`), 0o644)

	script := strings.NewReplacer("/proc/", dir+"/proc/", "/etc/docker/", dir+"/etc/docker/", `= 0 ]`, `= `+strconv.Itoa(os.Getuid())+` ]`).Replace(dockerAPIScript)
	out, err := exec.Command("/bin/sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"envsecret", "proxysecret", "logs:514"} {
		if strings.Contains(string(out), s) {
			t.Fatalf("%q left the host:\n%s", s, out)
		}
	}
	got, why := parseDockerAPI(string(out))
	want := []DockerAPI{
		{Hosts: []string{"tcp://0.0.0.0:2375"}},             // daemon.json says tls false
		{Hosts: []string{"tcp://10.0.0.5:2376"}, TLS: true}, // tlsverify false beats DOCKER_TLS_VERIFY
	}
	if why != "" || !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v (%q)\nwant %+v\noutput:\n%s", got, why, want, out)
	}
	if got, why := parseDockerAPI(strings.TrimSuffix(string(out), "@@end\n")); got != nil || why == "" {
		t.Error("output without @@end parsed")
	}
}

// How dockerd 29.9 combines its TLS settings (checked in the lab).
func TestDockerAPISettings(t *testing.T) {
	parse := func(args []string, extra ...string) DockerAPI {
		t.Helper()
		s := "@@dockerd 1\n"
		for _, a := range append([]string{"dockerd"}, args...) {
			s += "arg|" + a + "\n"
		}
		s += strings.Join(extra, "\n") + "\n@@end\n"
		got, why := parseDockerAPI(s)
		if why != "" || len(got) > 1 {
			t.Fatalf("%v: %+v %q", args, got, why)
		}
		if len(got) == 0 {
			return DockerAPI{}
		}
		return got[0]
	}
	h := "tcp://0.0.0.0:2376"
	cases := []struct {
		name  string
		args  []string
		extra []string
		open  bool
		tls   bool
	}{
		{"no tls flags", []string{"-H", h}, nil, true, false},
		{"--tls=false", []string{"-H", h, "--tls=false"}, nil, true, false},
		{"--tls verifies by default", []string{"-H", h, "--tls", "--tlscacert=/c/ca.pem"}, nil, false, true},
		{"--tlsverify", []string{"-H", h, "--tlsverify"}, nil, false, true},
		{"--tlsverify=false turns tls on without verifying", []string{"-H", h, "--tlsverify=false"}, nil, true, true},
		{"environment", []string{"-H", h, "--tls"}, []string{"env|DOCKER_TLS_VERIFY=1"}, false, true},
		{"empty environment variable", []string{"-H", h}, []string{"env|DOCKER_TLS_VERIFY="}, true, false},
		{"daemon.json", nil, []string{"json|host|" + h, "json|tls|true", "json|tlsverify|false"}, true, true},
		{"--host=", []string{"--host=" + h}, nil, true, false},
		{"-H joined", []string{"-H" + h}, nil, true, false},
	}
	for _, c := range cases {
		d := parse(c.args, c.extra...)
		if d.Open() != c.open || d.TLS != c.tls || !reflect.DeepEqual(d.Hosts, []string{h}) {
			t.Errorf("%s: %+v (open %v), want open %v tls %v", c.name, d, d.Open(), c.open, c.tls)
		}
	}
	if d := parse([]string{"-H", "unix:///var/run/docker.sock", "-H", "fd://"}); len(d.Hosts) != 0 {
		t.Errorf("no tcp hosts: %+v", d)
	}
}
