package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestContainerEscape(t *testing.T) {
	bind := func(src, dst string, rw bool) collect.Mount {
		return collect.Mount{Type: "bind", Source: src, Destination: dst, RW: rw}
	}
	f := &collect.Facts{IsRoot: true, Errors: map[string]string{}, Containers: []collect.Container{
		{Runtime: "docker", Name: "traefik", Image: "traefik:v3.1", Mounts: []collect.Mount{bind("/var/run/docker.sock", "/var/run/docker.sock", false)}},
		{Runtime: "docker", Name: "priv", Image: "alpine", Privileged: true, SecurityOpt: []string{"seccomp=unconfined"}},
		{Runtime: "docker", Name: "node-exporter", Image: "prom/node-exporter", Mounts: []collect.Mount{bind("/", "/host", false)}},
		{Runtime: "podman", Name: "cronedit", Image: "alpine", Mounts: []collect.Mount{bind("/etc/cron.d", "/cron", true)}},
		{Runtime: "docker", Name: "periodic", Image: "alpine", Mounts: []collect.Mount{bind("/etc/periodic/", "/periodic", true)}}, // Alpine's cron
		{Runtime: "docker", Name: "pidlabel", Image: "alpine", PidMode: "host", SecurityOpt: []string{"label=disable"}},            // Docker adds it
		{Runtime: "docker", Name: "reader", Image: "alpine", Mounts: []collect.Mount{bind("/etc/shadow", "/shadow", false)}},
		{Runtime: "docker", Name: "top", Image: "alpine", PidMode: "host"},
		{Runtime: "docker", Name: "debugger", Image: "alpine", PidMode: "host", CapAdd: []string{"CAP_SYS_PTRACE"}},
		{Runtime: "docker", Name: "fuse", Image: "alpine", CapAdd: []string{"SYS_ADMIN"}},
		{Runtime: "docker", Name: "imager", Image: "alpine", Devices: []string{"/dev/sda"}},
		{Runtime: "docker", Name: "loose", Image: "alpine", SecurityOpt: []string{"apparmor:unconfined"}},
		{Runtime: "docker", Name: "rundir", Image: "alpine", Mounts: []collect.Mount{bind("/run", "/hostrun", false)}},
		// Nothing to report: a named volume (under /var/lib/docker, but not
		// a host path the container chose), app data, certificates, the
		// host's /proc for metrics, a GPU and an extra network capability.
		{Runtime: "docker", Name: "web", Image: "nginx", NetworkMode: "host", CapAdd: []string{"NET_ADMIN"}, Devices: []string{"/dev/dri/renderD128"},
			Mounts: []collect.Mount{
				{Type: "volume", Source: "/var/lib/docker/volumes/web/_data", Destination: "/data", RW: true},
				bind("/srv/www", "/usr/share/nginx/html", true),
				bind("/etc/letsencrypt", "/etc/letsencrypt", true),
				bind("/proc", "/host/proc", false),
			}},
	}}
	got, skip := containerEscape.Run(f)
	if skip != "" {
		t.Fatal(skip)
	}
	want := map[string]struct {
		sev    Severity
		detail string
	}{
		"traefik":       {High, "socket /var/run/docker.sock mounted"},
		"priv":          {High, "runs privileged"},
		"node-exporter": {High, "host's / mounted, which holds root's control sockets (container runtime, systemd, D-Bus system bus)"},
		"cronedit":      {High, "can write the host's /etc/cron.d"},
		"periodic":      {High, "can write the host's /etc/periodic/"},
		"pidlabel":      {Medium, "shares the host's process namespace (sees and can signal every host process)"},
		"reader":        {Medium, "can read the host's /etc/shadow"},
		"top":           {Medium, "shares the host's process namespace"},
		"debugger":      {High, "can trace the host's processes"},
		"fuse":          {High, "has the SYS_ADMIN capability"},
		"imager":        {High, "raw access to the host device /dev/sda"},
		"loose":         {Low, "runs without apparmor confinement"},
		"rundir":        {High, "host's /run mounted"},
	}
	seen := map[string]bool{}
	for _, g := range got {
		name := strings.Fields(g.Title)[1]
		seen[name] = true
		w, ok := want[name]
		switch {
		case !ok:
			t.Errorf("unexpected finding: %+v", g)
		case g.CheckID != "CTR-001" || g.Severity != w.sev || !strings.Contains(g.Detail, w.detail):
			t.Errorf("%s: %v %q, want %v %q", name, g.Severity, g.Detail, w.sev, w.detail)
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no finding for %s", name)
		}
	}
	for _, g := range got {
		switch {
		case strings.HasPrefix(g.Title, "Container priv ") && strings.Contains(g.Detail, "seccomp"):
			t.Errorf("privileged already covers seccomp: %q", g.Detail)
		case strings.HasPrefix(g.Title, "Container pidlabel ") && strings.Contains(g.Detail, "label"):
			t.Errorf("label=disable is Docker's own doing: %q", g.Detail)
		case strings.HasPrefix(g.Title, "Container traefik ") && (!strings.Contains(g.Detail, "image traefik:v3.1") || !strings.Contains(g.Fix, "socket proxy")):
			t.Errorf("traefik: %+v", g)
		case strings.HasPrefix(g.Title, "Container loose ") && g.Title != "Container loose is less isolated from the host":
			t.Errorf("Low title: %q", g.Title)
		}
	}

	// What a socket mount means depends on the sockets the host has: none
	// at all, or systemd's and D-Bus's but no container API (podman without
	// its socket service).
	only := func(names ...string) map[string]Finding {
		m := map[string]Finding{}
		got, _ := containerEscape.Run(f)
		for _, g := range got {
			for _, n := range names {
				if strings.HasPrefix(g.Title, "Container "+n+" ") {
					m[n] = g
				}
			}
		}
		return m
	}
	f.ControlSockets = []string{}
	if m := only("traefik", "rundir", "node-exporter"); len(m) != 1 || m["node-exporter"].Severity != Medium {
		t.Errorf("no sockets: %+v", m)
	}
	f.ControlSockets = []string{"/run/systemd/private", "/run/dbus/system_bus_socket"}
	if m := only("traefik", "rundir"); len(m) != 1 || !strings.Contains(m["rundir"].Detail, "control sockets (systemd, D-Bus system bus)") {
		t.Errorf("systemd and D-Bus only: %+v", m)
	}

	f.Containers = []collect.Container{}
	if got, skip := containerEscape.Run(f); len(got) != 0 || skip != "" {
		t.Errorf("no containers: %+v %q", got, skip)
	}
	if _, skip := containerEscape.Run(&collect.Facts{Errors: map[string]string{}}); !strings.Contains(skip, "needs root") {
		t.Errorf("unprivileged: %q", skip)
	}
	if _, skip := containerEscape.Run(&collect.Facts{IsRoot: true, Errors: map[string]string{"containers": "docker: permission denied"}}); !strings.Contains(skip, "permission denied") {
		t.Errorf("runtime error: %q", skip)
	}
}
