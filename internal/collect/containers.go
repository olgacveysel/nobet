package collect

import (
	"cmp"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Container is a running container and the parts of its configuration
// that decide what it can do to the host.
type Container struct {
	Runtime     string          `json:"runtime"` // docker, podman, incus or lxd
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
	"/var/lib/incus/unix.socket", "/var/snap/lxd/common/lxd/unix.socket", "/var/lib/lxd/unix.socket",
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
` + instancesScript + `echo "@@end"
`

// instancesScript lists Incus and LXD containers from their "[lxc monitor]
// DIR NAME" processes, without the incus and lxc clients (the snap's
// creates ~/snap for root). Each instance's backup.yaml, which the daemon
// keeps with its whole configuration, is read through the monitor's root,
// so snap LXD's own mount namespace is reached too. awk passes on only the
// keys below: the rest (environment.* above all) stays on the host.
const instancesScript = `procs() {
  if command -v ps >/dev/null 2>&1; then ps -eo pid,args 2>/dev/null || ps -o pid,args
  else for p in /proc/[0-9]*; do echo "${p#/proc/} $(tr '\0' ' ' 2>/dev/null < $p/cmdline)"; done; fi
}
procs | awk '$2 == "[lxc" && $3 == "monitor]" && NF == 5 { print $1, $4, $5 }' |
while read -r pid dir name; do
  case $dir in */incus/*) rt=incus ;; */lxd/*) rt=lxd ;; *) continue ;; esac
  f=/proc/$pid/root$dir/$name/backup.yaml
  if [ ! -r "$f" ]; then echo "@@$rt error cannot read $dir/$name/backup.yaml"; continue; fi
  echo "@@instance $rt $name"
  awk 'function val() { v = $0; sub(/^ *[^ :]+: */, "", v); gsub(/["\047]/, "", v); return v }
    /^[^ ]/ { top = $1 }
    /^  [^ ]/ { sec = $1 }
    top != "container:" { next }
    sec == "expanded_config:" && /^    [^ ]/ {
      k = $1; sub(/:$/, "", k)
      if (k == "security.privileged" || k == "image.os" || k == "image.release" || k == "volatile.last_state.power") print "cfg|" k "|" val()
    }
    sec == "expanded_devices:" && /^    [^ ]/ { dev = $1; sub(/:$/, "", dev) }
    sec == "expanded_devices:" && /^      [^ ]/ {
      k = $1; sub(/:$/, "", k)
      if (k ~ /^(type|source|path|readonly|shift|pool)$/) print "dev|" dev "|" k "|" val()
    }' "$f"
done
`

// parseContainers reads containersScript output: the containers and the
// control sockets that exist. It returns nil and the reason when a runtime
// could not be read: a partial list would look complete.
func parseContainers(s string) ([]Container, []string, string) {
	out, sockets := []Container{}, []string{}
	rt, done := "", false
	var inst *instance
	endInstance := func() {
		if inst != nil {
			if c, running := inst.container(); running {
				out = append(out, c)
			}
			inst = nil
		}
	}
	for _, line := range lines(s) {
		if inst != nil {
			if p := strings.Split(line, "|"); p[0] == "cfg" && len(p) == 3 {
				inst.cfg[p[1]] = p[2]
				continue
			} else if p[0] == "dev" && len(p) == 4 {
				if inst.devs[p[1]] == nil {
					inst.devs[p[1]] = map[string]string{}
					inst.order = append(inst.order, p[1])
				}
				inst.devs[p[1]][p[2]] = p[3]
				continue
			}
			endInstance()
		}
		switch {
		case line == "@@end":
			done = true
		case strings.HasPrefix(line, "@@socket "):
			sockets = append(sockets, strings.TrimPrefix(line, "@@socket "))
		case strings.HasPrefix(line, "@@instance "):
			f := strings.Fields(line)
			if len(f) == 3 {
				inst = &instance{runtime: f[1], name: f[2], cfg: map[string]string{}, devs: map[string]map[string]string{}}
			}
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

// instance is an Incus or LXD container as instancesScript prints it.
type instance struct {
	runtime, name string
	cfg           map[string]string
	devs          map[string]map[string]string
	order         []string
}

// container turns an instance into a Container, and says whether it runs:
// a monitor process can outlive a failed start. Root in an unprivileged
// instance is an unprivileged host uid, so a host directory only counts
// there when it is shifted (idmapped: the container's root writes as the
// host's); checked on Incus 6.0 with a root-only file, which root inside
// could neither read nor write without shift=true and could with it.
// Block and character devices count either way: Incus creates the node
// for the container's root.
func (in *instance) container() (Container, bool) {
	c := Container{Runtime: in.runtime, Name: in.name, Privileged: in.cfg["security.privileged"] == "true",
		Image: strings.TrimSpace(in.cfg["image.os"] + " " + in.cfg["image.release"])}
	for _, name := range in.order {
		d := in.devs[name]
		switch d["type"] {
		case "disk":
			if !strings.HasPrefix(d["source"], "/") || d["pool"] != "" || d["path"] == "/" {
				continue // a storage volume, or the root disk
			}
			if c.Privileged || d["shift"] == "true" {
				c.Mounts = append(c.Mounts, Mount{Type: "bind", Source: d["source"], Destination: d["path"], RW: d["readonly"] != "true"})
			}
		case "unix-block", "unix-char":
			if p := cmp.Or(d["source"], d["path"]); p != "" {
				c.Devices = append(c.Devices, p)
			}
		}
	}
	return c, in.cfg["volatile.last_state.power"] == "RUNNING"
}
