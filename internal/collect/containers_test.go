package collect

import (
	"embed"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Real inspect output with containerFormat: Docker 27 and podman 5.8 (db
// publishes a port on IPv4 and IPv6).
const (
	dockerWeb    = `{"name":"/web","image":"alpine:3.22","privileged":false,"pid":"","net":"bridge","cap_add":null,"security_opt":null,"mounts":[{"Type":"volume","Name":"webdata","Source":"/var/lib/docker/volumes/webdata/_data","Destination":"/data","Driver":"local","Mode":"z","RW":true,"Propagation":""},{"Type":"bind","Source":"/srv","Destination":"/srv","Mode":"","RW":true,"Propagation":"rprivate"}],"devices":[]}`
	dockerCapsys = `{"name":"/capsys","image":"alpine:3.22","privileged":false,"pid":"","net":"bridge","cap_add":["SYS_ADMIN"],"security_opt":null,"mounts":[],"devices":[]}`
	dockerDB     = `{"name":"/db","image":"alpine:3.22","privileged":false,"pid":"","net":"bridge","cap_add":null,"security_opt":null,"mounts":[],"devices":[],"ports":{"5432/tcp":[{"HostIp":"0.0.0.0","HostPort":"5432"},{"HostIp":"::","HostPort":"5432"}]}}`
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
	idWeb, idCap, idRun, idDB := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), strings.Repeat("d", 64)
	write("docker", `#!/bin/sh
case "$1" in
--version) [ -n "$SHIM" ] && echo "podman version 5.8.9" || echo "Docker version 27.3.1, build ce12230" ;;
ps)
  [ -n "$DOWN" ] && { echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?" >&2; exit 1; }
  [ -n "$DENIED" ] && { echo "permission denied while trying to connect to the Docker daemon socket" >&2; exit 1; }
  echo "WARNING: Error loading config file" >&2
  echo `+idWeb+`; echo `+idCap+`; echo `+idDB+` ;;
inspect)
  case "$*" in *`+idWeb+`*`+idCap+`*`+idDB+`*) ;; *) exit 1 ;; esac
  echo '`+dockerWeb+`'; echo '`+dockerCapsys+`'; echo '`+dockerDB+`' ;;
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
	db := Container{Runtime: "docker", Name: "db", Image: "alpine:3.22", NetworkMode: "bridge", Ports: []PublishedPort{
		{Proto: "tcp", HostIP: "0.0.0.0", HostPort: 5432, Port: 5432}, {Proto: "tcp", HostIP: "::", HostPort: 5432, Port: 5432}}}
	prun := Container{Runtime: "podman", Name: "prun", Image: "docker.io/library/alpine:3.22", PidMode: "private", NetworkMode: "host",
		CapAdd: []string{}, SecurityOpt: []string{}, Mounts: []Mount{{Type: "bind", Source: "/run", Destination: "/hostrun"}}}

	// podman has no storage yet: it is left alone, since podman ps would
	// create it.
	if got, why := run(); why != "" || !reflect.DeepEqual(got, []Container{web, capsys, db}) {
		t.Errorf("docker only: %q\n%+v", why, got)
	}
	if !reflect.DeepEqual(sockets, []string{sock}) {
		t.Errorf("sockets: %v, want %v", sockets, sock)
	}
	os.Mkdir(storage, 0o700)
	if got, why := run(); why != "" || !reflect.DeepEqual(got, []Container{web, capsys, db, prun}) {
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

// incusFiles are real backup.yaml files (Incus 6.0, Debian 13), embedded so
// the test binary runs anywhere (CI's scripts job).
//
//go:embed testdata/incus/*.yaml
var incusFiles embed.FS

// Incus and LXD instances come from their monitor processes and
// backup.yaml: one unprivileged and running, with host directories (plain,
// shifted, read-only), the Incus socket and a block device; one privileged
// and stopped, which the test also starts by editing its last power state.
func TestInstancesScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	put := func(p, content string) {
		t.Helper()
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	read := func(name string) string {
		t.Helper()
		b, err := incusFiles.ReadFile("testdata/incus/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	unpriv, priv := read("unprivileged-running.yaml"), read("privileged-stopped.yaml")
	// Each monitor's root is dir/<pid>; the script reads /proc/<pid>/root.
	put(dir+"/93/var/lib/incus/containers/c2/backup.yaml", unpriv)
	put(dir+"/94/var/lib/incus/containers/c1/backup.yaml", priv)
	put(dir+"/95/var/lib/incus/containers/c4/backup.yaml", strings.Replace(priv, "volatile.last_state.power: STOPPED", "volatile.last_state.power: RUNNING", 2))
	put(dir+"/96/var/snap/lxd/common/lxd/containers/web/backup.yaml", unpriv)
	ps := `#!/bin/sh
cat <<'X'
    PID COMMAND
      1 /sbin/init
     93 [lxc monitor] /var/lib/incus/containers c2
     94 [lxc monitor] /var/lib/incus/containers c1
     95 [lxc monitor] /var/lib/incus/containers c4
     96 [lxc monitor] /var/snap/lxd/common/lxd/containers web
     97 [lxc monitor] /var/lib/lxc old
     98 grep [lxc monitor] x
X
`
	os.WriteFile(filepath.Join(bin, "ps"), []byte(ps), 0o755)
	run := func() string {
		t.Helper()
		cmd := exec.Command("/bin/sh", "-c", strings.ReplaceAll(instancesScript, "/proc/$pid/root", dir+"/$pid")+"echo @@end\n")
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "labsecret") {
			t.Fatalf("an instance's environment left the host:\n%s", out)
		}
		return string(out)
	}
	got, _, why := parseContainers(run())
	// Unprivileged: only the shifted directory counts, and the block device.
	c2 := Container{Runtime: "incus", Name: "c2", Image: "Alpine 3.22", Devices: []string{"/dev/loop0"},
		Mounts: []Mount{{Type: "bind", Source: "/var/lib/incus/hostdir", Destination: "/mnt/shifted", RW: true}}}
	web := c2
	web.Runtime, web.Name = "lxd", "web"
	c4 := Container{Runtime: "incus", Name: "c4", Image: "Alpine 3.22", Privileged: true}
	if want := []Container{c2, c4, web}; why != "" || !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v (%q)\nwant %+v", got, why, want)
	}

	// Privileged, every host directory counts, read-only ones as such.
	put(dir+"/95/var/lib/incus/containers/c4/backup.yaml", strings.Replace(unpriv, "    security.nesting: \"true\"\n", "    security.nesting: \"true\"\n    security.privileged: \"true\"\n", 2))
	got, _, _ = parseContainers(run())
	var mounts []string
	for _, m := range got[1].Mounts {
		mounts = append(mounts, m.Destination+map[bool]string{true: " rw", false: " ro"}[m.RW])
	}
	if want := []string{"/mnt/etc rw", "/mnt/plain rw", "/mnt/ro ro", "/mnt/shifted rw", "/mnt/incus.sock rw"}; !got[1].Privileged || !reflect.DeepEqual(mounts, want) {
		t.Errorf("privileged c4: %+v\nmounts %v, want %v", got[1], mounts, want)
	}

	os.Remove(dir + "/93/var/lib/incus/containers/c2/backup.yaml")
	if got, _, why := parseContainers(run()); got != nil || !strings.Contains(why, "cannot read /var/lib/incus/containers/c2/backup.yaml") {
		t.Errorf("unreadable backup.yaml: %q %+v", why, got)
	}
}
