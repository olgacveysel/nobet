package collect

import (
	"encoding/json"
	"strings"
	"testing"
)

// The scan history stores Facts. Bulky listings that only a scan needs
// stay out of it; their results stay in.
func TestFactsJSONLeavesOutBulk(t *testing.T) {
	f := Facts{
		RootJobs:       []RootJob{{Kind: "cron", Source: "/etc/crontab", Paths: []string{"/usr/local/bin/backup"}}},
		Paths:          map[string]PathEntry{"/usr/local/bin/backup": {}},
		Links:          map[string]string{"/sbin": "/usr/sbin"},
		Interpreters:   map[string]string{"/usr/local/bin/backup": "/bin/sh"},
		Calls:          map[string][]string{"/usr/local/bin/backup": {"/etc/backup.conf"}},
		Containers:     []Container{{Runtime: "docker", Name: "traefik"}},
		ControlSockets: []string{"/var/run/docker.sock"},
		RootWritable:   []WritablePath{{Path: "/usr/local/bin/backup"}},
		PrivateKeys:    []PrivateKey{{Path: "/home/alice/.ssh/id_ed25519"}},
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, gone := range []string{"RootJobs", `"Paths"`, `"Links"`, "Interpreters", `"Calls"`, "Containers", "traefik", "ControlSockets", "docker.sock"} {
		if strings.Contains(s, gone) {
			t.Errorf("history keeps %s: %s", gone, s)
		}
	}
	for _, kept := range []string{"RootWritable", "PrivateKeys"} {
		if !strings.Contains(s, kept) {
			t.Errorf("history lost %s", kept)
		}
	}
}
