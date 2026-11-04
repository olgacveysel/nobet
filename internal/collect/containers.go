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
` + instancesScript + podsScript + `echo "@@end"
`

// podsScript lists the running Kubernetes containers on a node through
// crictl, which asks the kubelet's container runtime (containerd or CRI-O)
// and changes nothing. Only on a node: a kubelet (or k3s, or RKE2, which
// run their own) is running. crictl inspect shows every container's
// environment, and pods carry annotations that can hold their whole spec,
// so awk follows the JSON's nesting and passes on only the paths below.
const podsScript = `kube=
for p in /proc/[0-9]*; do
  { read -r comm < $p/comm; } 2>/dev/null || continue
  case $comm in kubelet | k3s | k3s-server | k3s-agent | rke2) kube=$comm; break ;; esac
done
if [ -n "$kube" ]; then
  cri=$(command -v crictl 2>/dev/null)
  if [ -z "$cri" ] && [ -x /var/lib/rancher/rke2/bin/crictl ]; then
    cri=/var/lib/rancher/rke2/bin/crictl
    export CRI_CONFIG_FILE=/var/lib/rancher/rke2/agent/etc/crictl.yaml
  fi
  only='{
    line = $0; sub(/^[ \t]+/, "", line); sub(/[ \t]*,?[ \t]*$/, "", line)
    key = ""; val = line
    if (match(line, /^"[^"]*"[ \t]*:/)) {
      key = substr(line, 2, RLENGTH - 1); sub(/"[ \t]*:$/, "", key)
      val = substr(line, RLENGTH + 1); sub(/^[ \t]+/, "", val)
    }
    if (val == "{" && key == "" && !open) { open = 1; next }
    if (val == "{" || val == "[") { d++; st[d] = (key == "" ? "[]" : key); next }
    if (val == "}" || val == "]") { if (d > 0) d--; else open = 0; next }
    p = ""; for (i = 1; i <= d; i++) p = p "." st[i]
    p = p "." (key == "" ? "[]" : key)
    if (p ~ /^\.status\.(metadata\.name|metadata\.namespace|image\.image|labels\.io\.kubernetes\.pod\.(name|namespace))$/ ||
        p ~ /^\.status\.mounts\.\[\]\.(hostPath|containerPath|readonly)$/ ||
        p ~ /^\.status\.linux\.namespaces\.options\.(pid|network|ipc)$/ ||
        p ~ /^\.info\.(config\.linux\.security_context\.)?privileged$/ ||
        p ~ /^\.info\.runtimeSpec\.process\.capabilities\.bounding\.\[\]$/) print "k8s|" p "|" val
  }'
  if [ -z "$cri" ]; then
    echo "@@kubernetes error $kube is running but crictl is not installed, so its pods cannot be listed"
  elif ! pods=$($cri pods -q --state ready 2>/dev/null) || ! ctrs=$($cri ps -q --state running 2>/dev/null); then
    echo "@@kubernetes error crictl cannot reach the container runtime"
  else
    echo "@@kubernetes"
    for id in $pods; do echo "@@pod"; $cri inspectp $id 2>/dev/null | awk "$only"; done
    for id in $ctrs; do echo "@@ctr"; $cri inspect $id 2>/dev/null | awk "$only"; done
  fi
fi
`

// instancesScript lists Incus, LXD and plain LXC containers from their
// "[lxc monitor] DIR NAME" processes run by root (an account's own LXC
// containers cannot reach more than it), without the incus and lxc clients
// (the snap's creates ~/snap for root). Each Incus or LXD instance's
// backup.yaml, which the daemon keeps with its whole configuration, and an
// LXC container's config are read through the monitor's root, so snap
// LXD's own mount namespace is reached too. awk passes on only the keys
// below: the rest (environment.* and lxc.environment above all) stays on
// the host.
const instancesScript = `procs() {
  if command -v ps >/dev/null 2>&1; then ps -eo pid,uid,args 2>/dev/null || ps -o pid,uid,args
  else for p in /proc/[0-9]*; do echo "${p#/proc/} $(stat -c %u $p 2>/dev/null) $(tr '\0' ' ' 2>/dev/null < $p/cmdline)"; done; fi
}
procs | awk '$2 == "0" && $3 == "[lxc" && $4 == "monitor]" && NF == 6 { print $1, $5, $6 }' |
while read -r pid dir name; do
  case $dir in */incus/*) rt=incus ;; */lxd/*) rt=lxd ;; *) rt=lxc ;; esac
  if [ $rt = lxc ]; then
    # LXC's own config: privileged without lxc.idmap; host paths it
    # bind-mounts (idmap= in the options shifts them like Incus's shift).
    f=/proc/$pid/root$dir/$name/config
    if [ ! -r "$f" ]; then echo "@@lxc error cannot read $dir/$name/config"; continue; fi
    echo "@@instance lxc $name"
    awk '{ l = $0; sub(/^[ \t]+/, "", l) }
      l ~ /^lxc\.idmap[ \t]*=/ { idmap = 1 }
      l ~ /^lxc\.mount\.entry[ \t]*=/ {
        v = l; sub(/^[^=]*=[ \t]*/, "", v); split(v, a, /[ \t]+/)
        if (a[1] !~ /^\//) next
        n++; d = "m" n
        print "dev|" d "|type|" (a[1] ~ /^\/dev\// ? "unix-block" : "disk")
        print "dev|" d "|source|" a[1]
        print "dev|" d "|path|/" a[2]
        if (("," a[4] ",") ~ /,ro,/) print "dev|" d "|readonly|true"
        if (a[4] ~ /idmap=/) print "dev|" d "|shift|true"
      }
      END { print "cfg|security.privileged|" (idmap ? "false" : "true"); print "cfg|volatile.last_state.power|RUNNING" }' "$f"
    continue
  fi
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
	var k8s []*criRecord
	for _, line := range lines(s) {
		if strings.HasPrefix(line, "k8s|") && len(k8s) > 0 {
			p, v, _ := strings.Cut(line[len("k8s|"):], "|")
			if u, err := strconv.Unquote(v); err == nil {
				v = u
			}
			r := k8s[len(k8s)-1]
			r.pairs = append(r.pairs, [2]string{p, v})
			continue
		}
		if line == "@@pod" || line == "@@ctr" {
			k8s = append(k8s, &criRecord{pod: line == "@@pod"})
			continue
		}
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
	return append(out, kubeContainers(k8s)...), sockets, ""
}

// criRecord is a pod (crictl inspectp) or container (crictl inspect) as
// podsScript prints it: JSON paths and values, in order.
type criRecord struct {
	pod   bool
	pairs [][2]string
}

func (r *criRecord) get(path string) string {
	for _, p := range r.pairs {
		if p[0] == path {
			return p[1]
		}
	}
	return ""
}

// kubeContainers turns crictl records into Containers named
// namespace/pod/container, with their pod's host namespaces. A privileged
// container gets every capability, so capabilities are only listed for
// the others.
func kubeContainers(recs []*criRecord) []Container {
	type ns struct{ pid, net string }
	pods := map[string]ns{}
	for _, r := range recs {
		if r.pod {
			pods[r.get(".status.metadata.namespace")+"/"+r.get(".status.metadata.name")] = ns{
				pid: r.get(".status.linux.namespaces.options.pid"), net: r.get(".status.linux.namespaces.options.network")}
		}
	}
	var out []Container
	for _, r := range recs {
		if r.pod {
			continue
		}
		pod := r.get(".status.labels.io.kubernetes.pod.namespace") + "/" + r.get(".status.labels.io.kubernetes.pod.name")
		// containerd says privileged in the CRI config it keeps, CRI-O at
		// the top of its info (checked: containerd 2.1, CRI-O 1.32).
		c := Container{Runtime: "kubernetes", Name: pod + "/" + r.get(".status.metadata.name"), Image: r.get(".status.image.image"),
			Privileged: r.get(".info.config.linux.security_context.privileged") == "true" || r.get(".info.privileged") == "true"}
		if p, ok := pods[pod]; ok {
			if p.pid == "NODE" {
				c.PidMode = "host"
			}
			if p.net == "NODE" {
				c.NetworkMode = "host"
			}
		}
		for _, p := range r.pairs {
			switch p[0] {
			case ".status.mounts.[].containerPath":
				c.Mounts = append(c.Mounts, Mount{Type: "bind", Destination: p[1], RW: true})
			case ".status.mounts.[].hostPath":
				if n := len(c.Mounts); n > 0 {
					c.Mounts[n-1].Source = p[1]
				}
			case ".status.mounts.[].readonly":
				if n := len(c.Mounts); n > 0 {
					c.Mounts[n-1].RW = p[1] != "true"
				}
			case ".info.runtimeSpec.process.capabilities.bounding.[]":
				if !c.Privileged {
					c.CapAdd = append(c.CapAdd, p[1])
				}
			}
		}
		out = append(out, c)
	}
	return out
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
