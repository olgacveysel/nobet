package collect

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Real inspect output with containerFormat: Docker 27 and podman 5.8.
const (
	dockerWeb    = `{"name":"/web","image":"alpine:3.22","privileged":false,"pid":"","net":"bridge","cap_add":null,"security_opt":null,"mounts":[{"Type":"volume","Name":"webdata","Source":"/var/lib/docker/volumes/webdata/_data","Destination":"/data","Driver":"local","Mode":"z","RW":true,"Propagation":""},{"Type":"bind","Source":"/srv","Destination":"/srv","Mode":"","RW":true,"Propagation":"rprivate"}],"devices":[]}`
	dockerCapsys = `{"name":"/capsys","image":"alpine:3.22","privileged":false,"pid":"","net":"bridge","cap_add":["SYS_ADMIN"],"security_opt":null,"mounts":[],"devices":[]}`
	podmanRun    = `{"name":"prun","image":"docker.io/library/alpine:3.22","privileged":false,"pid":"private","net":"host","cap_add":[],"security_opt":[],"mounts":[{"Type":"bind","Source":"/run","Destination":"/hostrun","Driver":"","Mode":"","Options":["rbind"],"RW":false,"Propagation":"rprivate"}],"devices":[]}`
)

func TestContainersScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	if strings.Contains(containerFormat, "Env") || strings.Contains(containerFormat, "{{json .}}") {
		t.Fatal("the inspect format must not take the environment")
	}
	dir := t.TempDir()
	bin, storage := filepath.Join(dir, "bin"), filepath.Join(dir, "storage")
	os.Mkdir(bin, 0o755)
	// The control sockets live under dir: the one that exists is a real
	// socket, as on a Docker host.
	os.MkdirAll(filepath.Join(dir, "run"), 0o755)
	sock := filepath.Join(dir, "run", "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	idWeb, idCap, idRun := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	write("docker", `#!/bin/sh
case "$1" in
--version) [ -n "$SHIM" ] && echo "podman version 5.8.9" || echo "Docker version 27.3.1, build ce12230" ;;
ps)
  [ -n "$DOWN" ] && { echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1; }
  [ -n "$DENIED" ] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
  echo "WARNING: Error loading config file" >&2
  echo `+idWeb+`; echo `+idCap+` ;;
inspect)
  case "$*" in *`+idWeb+`*`+idCap+`*) ;; *) exit 1 ;; esac
  echo '`+dockerWeb+`'; echo '`+dockerCapsys+`' ;;
esac
`)
	write("podman", `#!/bin/sh
echo 'time="2026-10-21T14:50:58Z" level=warning msg="Using cgroups-v1 which is deprecated"' >&2
case "$1" in
ps) echo `+idRun+` ;;
inspect) [ "$4" = `+idRun+` ] && echo '`+podmanRun+`' ;;
esac
`)

	var sockets []string
	run := func(env ...string) ([]Container, string) {
		t.Helper()
		script := strings.ReplaceAll(containersScript, "/var/lib/containers/storage", storage)
		script = strings.ReplaceAll(script, " /var/run/", " "+dir+"/var/run/")
		script = strings.ReplaceAll(script, " /run/", " "+dir+"/run/")
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(append(os.Environ(), "PATH="+bin+":/usr/bin:/bin"), env...)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		cs, socks, why := parseContainers(string(out))
		sockets = socks
		return cs, why
	}
	web := Container{Runtime: "docker", Name: "web", Image: "alpine:3.22", NetworkMode: "bridge", Mounts: []Mount{
		{Type: "volume", Source: "/var/lib/docker/volumes/webdata/_data", Destination: "/data", RW: true},
		{Type: "bind", Source: "/srv", Destination: "/srv", RW: true},
	}}
	capsys := Container{Runtime: "docker", Name: "capsys", Image: "alpine:3.22", NetworkMode: "bridge", CapAdd: []string{"SYS_ADMIN"}}
	prun := Container{Runtime: "podman", Name: "prun", Image: "docker.io/library/alpine:3.22", PidMode: "private", NetworkMode: "host",
		CapAdd: []string{}, SecurityOpt: []string{}, Mounts: []Mount{{Type: "bind", Source: "/run", Destination: "/hostrun"}}}

	// podman has no storage yet: it is left alone, since podman ps would
	// create it.
	if got, why := run(); why != "" || !reflect.DeepEqual(got, []Container{web, capsys}) {
		t.Errorf("docker only: %q\n%+v", why, got)
	}
	if !reflect.DeepEqual(sockets, []string{sock}) {
		t.Errorf("sockets: %v, want %v", sockets, sock)
	}
	os.Mkdir(storage, 0o700)
	if got, why := run(); why != "" || !reflect.DeepEqual(got, []Container{web, capsys, prun}) {
		t.Errorf("docker and podman: %q\n%+v", why, got)
	}
	// A daemon that is not running has no containers; podman-docker is
	// podman, listed once.
	for _, env := range []string{"DOWN=1", "SHIM=1"} {
		if got, why := run(env); why != "" || !reflect.DeepEqual(got, []Container{prun}) {
			t.Errorf("%s: %q\n%+v", env, why, got)
		}
	}
	// Any other failure leaves the list unknown rather than short.
	if got, why := run("DENIED=1"); got != nil || !strings.Contains(why, "docker: permission denied") {
		t.Errorf("denied: %q %+v", why, got)
	}
	if got, _, why := parseContainers("@@docker\n" + dockerWeb + "\n"); got != nil || why == "" {
		t.Errorf("no end marker: %q %+v", why, got)
	}
	if got, why := run("PATH=" + t.TempDir()); why != "" || got == nil || len(got) != 0 { // only shell builtins
		t.Errorf("no runtimes installed: %q %+v", why, got)
	}
}
