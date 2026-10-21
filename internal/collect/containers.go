package collect

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Container is a running container and the parts of its configuration
// that decide what it can do to the host.
type Container struct {
	Runtime     string          `json:"runtime"` // docker or podman
	Name        string          `json:"name"`
	Image       string          `json:"image,omitempty"`
	Privileged  bool            `json:"privileged,omitempty"`
	PidMode     string          `json:"pid_mode,omitempty"`
	NetworkMode string          `json:"network_mode,omitempty"`
	CapAdd      []string        `json:"cap_add,omitempty"`
	SecurityOpt []string        `json:"security_opt,omitempty"`
	Mounts      []Mount         `json:"mounts,omitempty"`
	Devices     []string        `json:"devices,omitempty"` // host paths of devices passed in
	Ports       []PublishedPort `json:"ports,omitempty"`
}

// PublishedPort is a container port published on a host address.
type PublishedPort struct {
	Proto    string `json:"proto"`
	HostIP   string `json:"host_ip,omitempty"` // "", 0.0.0.0 or :: for every address
	HostPort int    `json:"host_port"`
	Port     int    `json:"port"` // inside the container
}

// Mount is a host path or volume mounted into a container.
type Mount struct {
	Type        string `json:"type,omitempty"` // bind, volume, tmpfs
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// ControlSockets are sockets through which root controls the host: the
// container runtimes' APIs, systemd's own socket and the D-Bus system bus.
// Each trusts a client whose uid is 0, which root in a container (without
// user namespaces) is.
var ControlSockets = []string{
	"/var/run/docker.sock", "/run/docker.sock",
	"/run/podman/podman.sock", "/var/run/podman/podman.sock",
	"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/crio/crio.sock", "/var/run/crio/crio.sock",
	"/run/systemd/private", "/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
}

// containerFormat picks the fields Container needs from `inspect`, one JSON
// object per line. Naming them keeps the environment, which often holds
// passwords, on the host.
const containerFormat = `{"name":{{json .Name}},"image":{{json .Config.Image}},"privileged":{{json .HostConfig.Privileged}},` +
	`"pid":{{json .HostConfig.PidMode}},"net":{{json .HostConfig.NetworkMode}},"cap_add":{{json .HostConfig.CapAdd}},` +
	`"security_opt":{{json .HostConfig.SecurityOpt}},"mounts":{{json .Mounts}},"devices":{{json .HostConfig.Devices}},` +
	`"ports":{{json .NetworkSettings.Ports}}}`

// containersScript lists the running containers of root's Docker daemon
// and of root's podman, and which ControlSockets exist. podman only runs
// where its storage already exists: on a fresh install, `podman ps` would
// create it. A docker command that is podman in disguise (podman-docker) is
// skipped, so nothing is listed twice. A daemon that is not running has no
// containers.
var containersScript = `for s in ` + strings.Join(ControlSockets, " ") + `; do
  [ -S "$s" ] && echo "@@socket $s"
done
for rt in docker podman; do
  command -v $rt >/dev/null 2>&1 || continue
  case $rt in
  docker) $rt --version 2>/dev/null | grep -qi podman && continue ;;
  podman) [ -d /var/lib/containers/storage ] || continue ;;
  esac
  # Warnings (podman on cgroups v1) go to stderr, so only stdout holds IDs.
  if ! ids=$($rt ps -q --no-trunc 2>/dev/null); then
    err=$($rt ps -q 2>&1 >/dev/null | tail -n 1)
    case $err in
    *"daemon running"* | *"No such file or directory"*) echo "@@$rt" ;;
    *) echo "@@$rt error $err" ;;
    esac
    continue
  fi
  ids=$(echo "$ids" | grep -E '^[0-9a-f]{12,64}$')
  echo "@@$rt"
  [ -z "$ids" ] || $rt inspect --format '` + containerFormat + `' $ids 2>/dev/null || echo "@@$rt error inspect failed"
done
echo "@@end"
`

// parseContainers reads containersScript output: the containers and the
// control sockets that exist. It returns nil and the reason when a runtime
// could not be read: a partial list would look complete.
func parseContainers(s string) ([]Container, []string, string) {
	out, sockets := []Container{}, []string{}
	rt, done := "", false
	for _, line := range lines(s) {
		switch {
		case line == "@@end":
			done = true
		case strings.HasPrefix(line, "@@socket "):
			sockets = append(sockets, strings.TrimPrefix(line, "@@socket "))
		case strings.HasPrefix(line, "@@"):
			f := strings.Fields(strings.TrimPrefix(line, "@@"))
			if len(f) == 0 {
				continue
			}
			if len(f) > 1 && f[1] == "error" {
				return nil, nil, f[0] + ": " + strings.Join(f[2:], " ")
			}
			rt = f[0]
		case rt != "" && strings.HasPrefix(line, "{"):
			var raw struct {
				Name        string   `json:"name"`
				Image       string   `json:"image"`
				Privileged  bool     `json:"privileged"`
				Pid         string   `json:"pid"`
				Net         string   `json:"net"`
				CapAdd      []string `json:"cap_add"`
				SecurityOpt []string `json:"security_opt"`
				Mounts      []struct {
					Type        string
					Source      string
					Destination string
					RW          bool
				} `json:"mounts"`
				Devices []struct {
					PathOnHost string
				} `json:"devices"`
				Ports map[string][]struct { // "80/tcp": where it is published; null if only exposed
					HostIP   string `json:"HostIp"`
					HostPort string
				} `json:"ports"`
			}
			if err := json.Unmarshal([]byte(line), &raw); err != nil {
				return nil, nil, rt + ": unreadable inspect output"
			}
			c := Container{Runtime: rt, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Image, Privileged: raw.Privileged,
				PidMode: raw.Pid, NetworkMode: raw.Net, CapAdd: raw.CapAdd, SecurityOpt: raw.SecurityOpt}
			for _, m := range raw.Mounts {
				c.Mounts = append(c.Mounts, Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW})
			}
			for _, d := range raw.Devices {
				c.Devices = append(c.Devices, d.PathOnHost)
			}
			for spec, binds := range raw.Ports {
				num, proto, _ := strings.Cut(spec, "/")
				port, err := strconv.Atoi(num)
				if err != nil {
					continue
				}
				for _, b := range binds {
					if hp, err := strconv.Atoi(b.HostPort); err == nil {
						c.Ports = append(c.Ports, PublishedPort{Proto: proto, HostIP: b.HostIP, HostPort: hp, Port: port})
					}
				}
			}
			sort.Slice(c.Ports, func(i, j int) bool {
				a, b := c.Ports[i], c.Ports[j]
				if a.HostPort != b.HostPort {
					return a.HostPort < b.HostPort
				}
				if a.Proto != b.Proto {
					return a.Proto < b.Proto
				}
				return a.HostIP < b.HostIP
			})
			out = append(out, c)
		}
	}
	if !done {
		return nil, nil, "the listing stopped early"
	}
	return out, sockets, ""
}
