package checks

import (
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/collect"
)

func TestPublishedPorts(t *testing.T) {
	port := func(proto, ip string, host, ctr int) collect.PublishedPort {
		return collect.PublishedPort{Proto: proto, HostIP: ip, HostPort: host, Port: ctr}
	}
	f := &collect.Facts{
		IsRoot: true,
		Errors: map[string]string{},
		// docker-proxy listens for the web container's port; with
		// userland-proxy off, db's port has no socket at all.
		Listeners: []collect.Listener{{Proto: "tcp", Addr: "0.0.0.0", Port: 22}, {Proto: "tcp", Addr: "0.0.0.0", Port: 8080}, {Proto: "tcp", Addr: "::", Port: 8080}},
		Firewall:  &collect.Firewall{UFW: "Status: active", IptChecked: true, IptInputPolicy: "DROP", IptInputRules: 4},
		Containers: []collect.Container{
			{Runtime: "docker", Name: "web", Ports: []collect.PublishedPort{port("tcp", "0.0.0.0", 8080, 80), port("tcp", "::", 8080, 80)}},
			{Runtime: "docker", Name: "db", Ports: []collect.PublishedPort{port("tcp", "0.0.0.0", 5432, 5432)}},
			{Runtime: "docker", Name: "cache", Ports: []collect.PublishedPort{port("tcp", "127.0.0.1", 6379, 6379)}}, // loopback only: fine
			{Runtime: "docker", Name: "intranet", Ports: []collect.PublishedPort{port("tcp", "10.0.0.5", 9000, 9000)}},
			{Runtime: "podman", Name: "metrics", Ports: []collect.PublishedPort{port("tcp", "", 9100, 9100)}},
		},
	}

	got, _ := exposedListeners.Run(f)
	var db, others *Finding
	for i := range got {
		switch {
		case got[i].Title == "PostgreSQL is listening on all interfaces":
			db = &got[i]
		case strings.Contains(got[i].Title, "other service(s)"):
			others = &got[i]
		default:
			t.Errorf("unexpected: %+v", got[i])
		}
	}
	if db == nil || db.Severity != High || db.Detail != "tcp/5432 (published by container db)" || !strings.Contains(db.Fix, "-p 127.0.0.1:5432:") || !strings.Contains(db.Fix, "ufw") {
		t.Errorf("published database: %+v", db)
	}
	if others == nil || others.Detail != "tcp/8080 (published by container web), tcp/9100 (published by container metrics)" {
		t.Errorf("others: %+v", others)
	}

	// ufw is active, but Docker's published ports go around it.
	got, _ = hostFirewall.Run(f)
	if len(got) != 1 || got[0].Severity != Low || got[0].Title != "The firewall does not filter the ports Docker publishes" ||
		got[0].Detail != "tcp/8080 (web), tcp/5432 (db), tcp/9000 (intranet): reachable from the network whatever ufw allows, since Docker forwards them before ufw sees them" {
		t.Errorf("bypass: %+v", got)
	}
	// Rules in DOCKER-USER are the supported way to filter them.
	f.Firewall.DockerUserRules = 2
	if got, _ := hostFirewall.Run(f); len(got) != 0 {
		t.Errorf("with DOCKER-USER rules: %+v", got)
	}
	// Without a firewall, NET-002 says so as before, counting published ports.
	f.Firewall = &collect.Firewall{UFW: "Status: inactive"}
	if got, _ := hostFirewall.Run(f); len(got) != 1 || got[0].Title != "No host firewall is filtering incoming traffic" || !strings.HasSuffix(got[0].Detail, "tcp/5432, tcp/8080, tcp/9100") {
		t.Errorf("no firewall: %+v", got)
	}
}
