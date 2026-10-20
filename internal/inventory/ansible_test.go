package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const iniInventory = `# production
mail.example.com

[web]
web[01:03].example.com
web-canary ansible_host=10.0.1.9 ansible_port=2222

[db]
db1 ansible_host=10.0.2.11 ansible_user=dba   # trailing note
db2 ansible_host=10.0.2.12

[db:vars]
ansible_user=postgres
ansible_port=2200

[prod:children]
web
db

[prod:vars]
ansible_user=deploy

[all:vars]
ansible_user=admin
ansible_python_interpreter=/usr/bin/python3

[local]
localhost ansible_connection=local
`

func TestLoadAnsibleINI(t *testing.T) {
	hosts, skipped, err := Load(write(t, iniInventory), "me", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{
		{Name: "mail.example.com", Addr: "mail.example.com", User: "admin"},
		{Name: "web01.example.com", Addr: "web01.example.com", User: "deploy"},
		{Name: "web02.example.com", Addr: "web02.example.com", User: "deploy"},
		{Name: "web03.example.com", Addr: "web03.example.com", User: "deploy"},
		{Name: "web-canary", Addr: "10.0.1.9", Port: 2222, User: "deploy"},
		{Name: "db1", Addr: "10.0.2.11", Port: 2200, User: "dba"},      // host var beats [db:vars]
		{Name: "db2", Addr: "10.0.2.12", Port: 2200, User: "postgres"}, // child group beats [prod:vars]
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got  %+v\nwant %+v", hosts, want)
	}
	if !reflect.DeepEqual(skipped, []string{"localhost"}) {
		t.Errorf("skipped = %q", skipped)
	}

	db, _, err := Load(write(t, iniInventory), "me", []string{"db"})
	if err != nil || len(db) != 2 || db[0].Name != "db1" {
		t.Errorf("-group db: %+v %v", db, err)
	}
	prod, _, _ := Load(write(t, iniInventory), "me", []string{"prod"})
	if len(prod) != 6 {
		t.Errorf("-group prod (children web and db): got %d hosts", len(prod))
	}
	if _, _, err := Load(write(t, iniInventory), "me", []string{"nope"}); err == nil || !strings.Contains(err.Error(), `no group "nope"`) {
		t.Errorf("unknown group: %v", err)
	}
	if _, _, err := Load(write(t, iniInventory), "me", []string{"db1"}); err == nil || !strings.Contains(err.Error(), "it is a host") {
		t.Errorf("host given as group: %v", err)
	}
}

// ansible-inventory -i inventory.yml --list (ansible-core 2.17), trimmed.
const listJSON = `{
    "_meta": {
        "hostvars": {
            "app1": {"ansible_host": "192.0.2.10", "ansible_user": "ops", "ansible_port": 2222},
            "app2": {"ansible_host": "192.0.2.11", "ansible_user": "ops"},
            "bastion": {"ansible_user": "jump"}
        }
    },
    "all": {"children": ["ungrouped", "app", "edge"]},
    "app": {"hosts": ["app1", "app2"]},
    "edge": {"hosts": ["bastion"]},
    "ungrouped": {}
}`

func TestLoadAnsibleJSON(t *testing.T) {
	hosts, _, err := Load(write(t, listJSON), "me", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{
		{Name: "app1", Addr: "192.0.2.10", Port: 2222, User: "ops"},
		{Name: "app2", Addr: "192.0.2.11", User: "ops"},
		{Name: "bastion", Addr: "bastion", User: "jump"},
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got  %+v\nwant %+v", hosts, want)
	}
	edge, _, _ := Load(write(t, listJSON), "me", []string{"edge"})
	if len(edge) != 1 || edge[0].Name != "bastion" {
		t.Errorf("-group edge: %+v", edge)
	}
}

func TestLoadPlainAndErrors(t *testing.T) {
	hosts, _, err := Load(write(t, "web01\n# a comment\nops@db01:2222  # primary\n[2001:db8::1]\n"), "me", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Host{
		{Name: "web01", Addr: "web01", User: "me"},
		{Name: "ops@db01:2222", Addr: "db01", Port: 2222, User: "ops"},
		{Name: "[2001:db8::1]", Addr: "2001:db8::1", User: "me"}, // not an Ansible [group]
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("got %+v", hosts)
	}
	cases := map[string]string{
		"all:\n  hosts:\n    web01:\n": "ansible-inventory -i",
		"---\nall:\n":                  "YAML inventories",
		"[web]\nweb01 port 22\n":       "line 2: want key=value",
		"[web:other]\nweb01\n":         "unknown section",
		"[web]\nweb[3:1]\n":            "bad range",
	}
	for in, want := range cases {
		if _, _, err := Load(write(t, in), "me", nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err %v, want %q", in, err, want)
		}
	}
	if _, _, err := Load(write(t, "web01\n"), "me", []string{"web"}); err == nil || !strings.Contains(err.Error(), "plain host list") {
		t.Errorf("-group on a plain list: %v", err)
	}
}

func TestExpandRange(t *testing.T) {
	cases := map[string][]string{
		"web[01:03]":   {"web01", "web02", "web03"},
		"db-[a:c].lan": {"db-a.lan", "db-b.lan", "db-c.lan"},
		"n[1:9:4]":     {"n1", "n5", "n9"},
		"r[1:2]-[a:b]": {"r1-a", "r1-b", "r2-a", "r2-b"},
		"plain.host":   {"plain.host"},
	}
	for in, want := range cases {
		if got, err := expandRange(in); err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("expandRange(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
