package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/olgacveysel/nobet/internal/collect"
)

// riskyPorts are services that should almost never be reachable from every
// interface. A host firewall may still protect them; that is checked later.
var riskyPorts = map[int]string{
	2375:  "Docker API (unencrypted)",
	2379:  "etcd",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	5984:  "CouchDB",
	6379:  "Redis",
	8500:  "Consul",
	9200:  "Elasticsearch",
	11211: "Memcached",
	27017: "MongoDB",
}

func wildcardAddr(addr string) bool {
	return addr == "0.0.0.0" || addr == "::" || addr == "*"
}

func loopbackAddr(addr string) bool {
	return strings.HasPrefix(addr, "127.") || addr == "::1" || addr == "localhost"
}

// dockerAPIPort is dockerd's plain-HTTP API: whoever reaches it can start a
// privileged container and so is root on the host.
const dockerAPIPort = 2375

var exposedListeners = Check{
	ID:    "NET-001",
	Title: "Services listening on all interfaces",
	Run: func(f *collect.Facts) ([]Finding, string) {
		if f.Listeners == nil {
			return nil, "could not list listening sockets: " + f.Errors["listeners"]
		}
		// Ports Docker publishes on every address count like listeners, and
		// say which container they lead to. With userland-proxy off they
		// have no listening socket at all.
		byKey := map[string][]string{}
		listeners := append([]collect.Listener(nil), f.Listeners...)
		for _, p := range dockerPublished(f) {
			if !wildcardAddr(p.HostIP) && p.HostIP != "" {
				continue
			}
			key := p.Proto + "/" + strconv.Itoa(p.HostPort)
			if byKey[key] == nil {
				listeners = append(listeners, collect.Listener{Proto: p.Proto, Addr: "0.0.0.0", Port: p.HostPort})
			}
			if !contains(byKey[key], p.Container) {
				byKey[key] = append(byKey[key], p.Container)
			}
		}
		via := func(key string) string {
			if cs := byKey[key]; len(cs) > 0 {
				return " (published by container " + strings.Join(cs, ", ") + ")"
			}
			return ""
		}
		seen := map[string]bool{}
		var out []Finding
		var others []string
		for _, l := range listeners {
			key := l.Proto + "/" + strconv.Itoa(l.Port)
			if l.Proto == "tcp" && l.Port == dockerAPIPort && !loopbackAddr(l.Addr) {
				if !seen[key] {
					seen[key] = true
					out = append(out, Finding{
						CheckID:  "NET-001",
						Severity: Critical,
						Title:    "Docker API without TLS is reachable from the network",
						Detail:   key + " on " + l.Addr + "; anyone who can connect can run a privileged container, which is root on this host",
						Fix:      "Remove the tcp:// listener from dockerd (-H or \"hosts\" in daemon.json), or switch to TLS with client certificates on port 2376",
					})
				}
				continue
			}
			if !wildcardAddr(l.Addr) {
				continue
			}
			if seen[key] {
				continue // same port on IPv4 and IPv6
			}
			seen[key] = true
			if name, ok := riskyPorts[l.Port]; ok && l.Proto == "tcp" {
				fnd := Finding{
					CheckID:  "NET-001",
					Severity: High,
					Title:    name + " is listening on all interfaces",
					Detail:   key + via(key),
					Fix:      "Bind it to localhost or a private interface, or restrict access with a firewall",
				}
				if byKey[key] != nil {
					fnd.Fix = "Publish it on 127.0.0.1 or a private address only (-p 127.0.0.1:" + strconv.Itoa(l.Port) + ":...), or not at all; host firewalls such as ufw do not filter the ports Docker publishes"
				}
				out = append(out, fnd)
				continue
			}
			if l.Port == 22 && l.Proto == "tcp" {
				continue
			}
			others = append(others, key+via(key))
		}
		if len(others) > 0 {
			sort.Strings(others)
			out = append(out, Finding{
				CheckID:  "NET-001",
				Severity: Info,
				Title:    fmt.Sprintf("%d other service(s) listening on all interfaces", len(others)),
				Detail:   strings.Join(others, ", "),
				Fix:      "Confirm each one is meant to be reachable from the network",
			})
		}
		return out, ""
	},
}

var hostFirewall = Check{
	ID:    "NET-002",
	Title: "Host firewall",
	Run: func(f *collect.Facts) ([]Finding, string) {
		fw := f.Firewall
		if fw == nil {
			return nil, unavailable(f, "firewall", "firewall state")
		}
		if fw.Active() {
			return dockerBypass(f), ""
		}
		// How much this matters depends on what is exposed.
		var exposed []string
		seen := map[string]bool{}
		listeners := append([]collect.Listener(nil), f.Listeners...)
		for _, p := range dockerPublished(f) {
			if wildcardAddr(p.HostIP) || p.HostIP == "" {
				listeners = append(listeners, collect.Listener{Proto: p.Proto, Addr: "0.0.0.0", Port: p.HostPort})
			}
		}
		for _, l := range listeners {
			key := l.Proto + "/" + strconv.Itoa(l.Port)
			if wildcardAddr(l.Addr) && !(l.Proto == "tcp" && l.Port == 22) && !seen[key] {
				seen[key] = true
				exposed = append(exposed, key)
			}
		}
		sort.Strings(exposed)
		fnd := Finding{
			CheckID:  "NET-002",
			Severity: Low,
			Title:    "No host firewall is filtering incoming traffic",
			Detail:   "no active ufw, firewalld, nftables input rules or iptables INPUT rules",
			Fix:      "Enable a default-deny inbound policy (ufw, firewalld or nftables) that allows only the services you intend to expose",
		}
		if !fw.Known() {
			fnd.Detail = "no firewall tools (ufw, firewalld, nft, iptables) were found"
		}
		if len(exposed) > 0 {
			fnd.Severity = Medium
			fnd.Detail += "; exposed on all interfaces: " + summarize(exposed, 8)
		}
		return []Finding{fnd}, ""
	},
}

// published is a port a container publishes on the host.
type published struct {
	collect.PublishedPort
	Container string
}

// dockerPublished lists the ports running Docker and podman containers
// publish on host addresses other than loopback.
func dockerPublished(f *collect.Facts) []published {
	var out []published
	for _, c := range f.Containers {
		for _, p := range c.Ports {
			if !loopbackAddr(p.HostIP) {
				out = append(out, published{p, c.Name})
			}
		}
	}
	return out
}

// dockerBypass reports the ports Docker publishes past an active host
// firewall. Docker sends them to the container through FORWARD after its
// own NAT rules, so INPUT rules, which are what ufw and most hand-written
// rule sets filter, never see them; DOCKER-USER is where they can be
// filtered.
func dockerBypass(f *collect.Facts) []Finding {
	if f.Firewall.DockerUserRules > 0 {
		return nil
	}
	var ports []string
	seen := map[string]bool{}
	for _, c := range f.Containers {
		if c.Runtime != "docker" {
			continue // podman's netavark is not Docker's rule set
		}
		for _, p := range c.Ports {
			key := p.Proto + "/" + strconv.Itoa(p.HostPort)
			if loopbackAddr(p.HostIP) || seen[key+c.Name] {
				continue
			}
			seen[key+c.Name] = true
			ports = append(ports, key+" ("+c.Name+")")
		}
	}
	if len(ports) == 0 {
		return nil
	}
	fw := "the firewall's INPUT rules"
	switch {
	case strings.HasPrefix(strings.ToLower(f.Firewall.UFW), "status: active"):
		fw = "ufw"
	case strings.TrimSpace(f.Firewall.Firewalld) == "running":
		fw = "firewalld"
	}
	return []Finding{{
		CheckID:  "NET-002",
		Severity: Low,
		Title:    "The firewall does not filter the ports Docker publishes",
		Detail:   summarize(ports, 8) + ": reachable from the network whatever " + fw + " allows, since Docker forwards them before " + fw + " sees them",
		Fix:      "Publish ports that need not be public on 127.0.0.1 or a private address (-p 127.0.0.1:8080:80), or filter them in the DOCKER-USER chain (iptables -I DOCKER-USER ...)",
	}}
}
