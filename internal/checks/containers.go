package checks

import (
	"fmt"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// hostTakeover are host paths that root runs or trusts: write access to
// any of them, to a directory above them or to anything below them, is
// root on the host.
var hostTakeover = []string{
	"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers", "/etc/sudoers.d",
	"/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly",
	"/etc/periodic", "/etc/init.d", "/etc/local.d", "/etc/rc.local", // Alpine and OpenRC
	"/etc/systemd", "/etc/ssh", "/etc/pam.d", "/etc/security", "/etc/profile", "/etc/profile.d", "/etc/environment",
	"/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/modprobe.d", "/etc/udev",
	"/etc/logrotate.conf", "/etc/logrotate.d", "/etc/apt/apt.conf.d", // commands run as root
	"/var/spool/cron", "/var/lib/docker", "/var/lib/containers",
	"/root", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
}

// hostSecrets are host paths whose contents (password hashes, SSH host
// and user keys) are worth stealing even read-only.
var hostSecrets = []string{"/etc/shadow", "/etc/ssh", "/root"}

// takeoverCaps are capabilities that let a container's root break out:
// mount and cgroup tricks, kernel modules, raw device and memory access,
// and reading any host file by handle.
var takeoverCaps = map[string]bool{"ALL": true, "SYS_ADMIN": true, "SYS_MODULE": true, "SYS_RAWIO": true, "DAC_READ_SEARCH": true}

// rawDisks are device paths that give raw access to host disks or memory.
var rawDisks = []string{"/dev/sd", "/dev/vd", "/dev/xvd", "/dev/hd", "/dev/nvme", "/dev/mmcblk", "/dev/dm-", "/dev/md", "/dev/mapper/", "/dev/mem", "/dev/kmem", "/dev/port"}

var containerEscape = Check{
	ID:    "CTR-001",
	Title: "Containers that can take over the host",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Containers == nil {
			return nil, unavailable(f, "containers", "container list")
		}
		sockets := f.ControlSockets
		if sockets == nil {
			sockets = collect.ControlSockets // not known: assume they exist
		}
		var out []Finding
		for _, c := range f.Containers {
			sev, reasons, fixes := containerRisks(c, sockets)
			if len(reasons) == 0 {
				continue
			}
			title := "Container " + c.Name + " can take over the host"
			switch sev {
			case Medium:
				title = "Container " + c.Name + " can reach into the host"
			case Low:
				title = "Container " + c.Name + " is less isolated from the host"
			}
			detail := strings.Join(reasons, "; ")
			if c.Image != "" {
				detail += fmt.Sprintf(" (%s, image %s)", c.Runtime, c.Image)
			}
			out = append(out, Finding{CheckID: "CTR-001", Severity: sev, Title: title, Detail: detail,
				Fix: strings.Join(fixes, " ") + " Allowlist the container by name if it is trusted with root on this host."})
		}
		return out, ""
	},
}

// containerRisks lists what a container's configuration lets it do to the
// host, the worst severity among them, and how to fix each. sockets are the
// host's control sockets: root in a container that can connect to one is
// root on the host, read-only mount or not, since connecting is not writing.
func containerRisks(c collect.Container, sockets []string) (Severity, []string, []string) {
	worst := Info
	var reasons, fixes []string
	add := func(sev Severity, reason, fix string) {
		if sev > worst {
			worst = sev
		}
		reasons = append(reasons, reason)
		if !contains(fixes, fix) {
			fixes = append(fixes, fix)
		}
	}
	if c.Privileged {
		add(High, "runs privileged (all capabilities and host devices)", "Drop --privileged and add only the capabilities or devices it needs.")
	}
	for _, m := range c.Mounts {
		if m.Type != "" && m.Type != "bind" {
			continue // named volumes and tmpfs hold no host paths
		}
		src := strings.TrimSuffix(m.Source, "/")
		if src == "" {
			src = "/"
		}
		under := socketsUnder(src, sockets)
		switch {
		case m.RW && underOrAbove(src, hostTakeover):
			add(High, "can write the host's "+m.Source, "Mount only the directory it needs, read-only where it can be.")
		case contains(sockets, src):
			fix := "Do not give it the socket."
			if socketName(src) == "container runtime" {
				fix = "Mount a socket proxy that allows only the API calls it needs (read-only container listing, for example) instead of the socket."
			}
			add(High, "has the host's "+socketName(src)+" socket "+m.Source+" mounted (root in the container can use it to run anything on the host)", fix)
		case len(under) > 0:
			add(High, "has the host's "+m.Source+" mounted, which holds root's control sockets ("+strings.Join(under, ", ")+")", "Do not mount the host's "+m.Source+"; mount only what it needs.")
		case underOrAbove(src, hostSecrets) || src == "/etc":
			add(Medium, "can read the host's "+m.Source+" (password hashes, SSH keys)", "Mount only the files it needs.")
		}
	}
	hostPID := c.PidMode == "host"
	for _, cp := range c.CapAdd {
		name := strings.TrimPrefix(strings.ToUpper(cp), "CAP_")
		switch {
		case takeoverCaps[name]:
			add(High, "has the "+name+" capability", "Remove --cap-add "+name+"; grant narrower capabilities if it needs some.")
		case name == "SYS_PTRACE" && hostPID:
			add(High, "can trace the host's processes (SYS_PTRACE with the host's PID namespace)", "Remove --pid host or the SYS_PTRACE capability.")
		}
	}
	if hostPID {
		add(Medium, "shares the host's process namespace (sees and can signal every host process)", "Remove --pid host.")
	}
	for _, d := range c.Devices {
		for _, p := range rawDisks {
			if strings.HasPrefix(d, p) {
				add(High, "has raw access to the host device "+d, "Pass in only the devices it needs; never disks or memory.")
				break
			}
		}
	}
	// label=disable (SELinux) is left out: Docker sets it by itself for
	// --pid host and --privileged.
	if !c.Privileged {
		for _, o := range c.SecurityOpt {
			switch strings.Replace(o, ":", "=", 1) {
			case "seccomp=unconfined", "apparmor=unconfined":
				add(Low, "runs without "+strings.SplitN(strings.Replace(o, ":", "=", 1), "=", 2)[0]+" confinement ("+o+")", "Remove --security-opt "+o+", or give it a profile that allows what it needs.")
			}
		}
	}
	return worst, reasons, fixes
}

// socketsUnder names the control sockets below a host directory.
func socketsUnder(src string, sockets []string) []string {
	var names []string
	for _, s := range sockets {
		if (src == "/" || strings.HasPrefix(s, src+"/")) && !contains(names, socketName(s)) {
			names = append(names, socketName(s))
		}
	}
	return names
}

// socketName says what a control socket controls.
func socketName(s string) string {
	switch {
	case strings.HasPrefix(s, "/run/systemd/"):
		return "systemd"
	case strings.Contains(s, "/dbus/"):
		return "D-Bus system bus"
	}
	return "container runtime"
}

// underOrAbove reports whether a host path is one of paths, a directory
// above one, or inside one.
func underOrAbove(src string, paths []string) bool {
	for _, p := range paths {
		if p == src || src == "/" || strings.HasPrefix(p, src+"/") || strings.HasPrefix(src, p+"/") {
			return true
		}
	}
	return false
}
