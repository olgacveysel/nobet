package sshconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/olgacveysel/nobet/internal/inventory"
)

// fake is an in-memory ssh_config: alias -> key -> values.
type fake map[string]map[string][]string

func (f fake) Get(alias, key string) string {
	if v := f[alias][strings.ToLower(key)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (f fake) GetAll(alias, key string) []string { return f[alias][strings.ToLower(key)] }

var conf = fake{
	"db": {
		"hostname":     {"10.0.0.21"},
		"user":         {"ops"},
		"port":         {"2222"},
		"identityfile": {"/keys/db_%r"},
		"proxyjump":    {"bastion"},
	},
	"bastion": {
		"hostname": {"bastion.example.com"},
		"user":     {"jump"},
	},
	"legacy": {"proxycommand": {"ssh -W %h:%p gw"}},
	"chain":  {"proxyjump": {"admin@gw1:2200,bastion"}},
}

func mustParse(t *testing.T, s, user string) inventory.Host {
	h, err := inventory.Parse(s, user)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestResolveAliasAndJump(t *testing.T) {
	got, err := Resolve(mustParse(t, "db", ""), conf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "10.0.0.21:2222" || got.User != "ops" || len(got.KeyFiles) != 1 || got.KeyFiles[0] != "/keys/db_ops" {
		t.Errorf("target: %+v", got)
	}
	if got.Jump == nil || got.Jump.Addr != "bastion.example.com:22" || got.Jump.User != "jump" || got.Jump.Jump != nil {
		t.Errorf("jump: %+v", got.Jump)
	}
}

func TestExplicitValuesWin(t *testing.T) {
	got, err := Resolve(mustParse(t, "root@db:22", ""), conf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "10.0.0.21:22" || got.User != "root" {
		t.Errorf("explicit user/port should win: %+v", got)
	}
}

func TestChainOrder(t *testing.T) {
	got, err := Resolve(mustParse(t, "chain", "me"), conf)
	if err != nil {
		t.Fatal(err)
	}
	// chain is reached through bastion, which is reached through gw1.
	if got.Jump == nil || got.Jump.Addr != "bastion.example.com:22" {
		t.Fatalf("first hop back should be bastion: %+v", got.Jump)
	}
	if gw := got.Jump.Jump; gw == nil || gw.Addr != "gw1:2200" || gw.User != "admin" {
		t.Errorf("outermost hop should be gw1: %+v", gw)
	}
}

func TestProxyCommandRejected(t *testing.T) {
	if _, err := Resolve(mustParse(t, "legacy", "me"), conf); err == nil {
		t.Error("ProxyCommand should be reported as unsupported")
	}
}

func TestNone(t *testing.T) {
	got, err := Resolve(mustParse(t, "db", "me"), None{})
	if err != nil || got.Addr != "db:22" || got.User != "me" || got.Jump != nil {
		t.Errorf("without ssh_config: %+v, %v", got, err)
	}
}

func TestLoadFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config")
	cfg := `Host db
  HostName 10.0.0.21
  Port 2222
  ProxyJump gw
Host gw
  HostName gw.example.com
  User jump
`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(mustParse(t, "db", "ops"), f)
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != "10.0.0.21:2222" || got.User != "ops" || got.Jump == nil || got.Jump.Addr != "gw.example.com:22" || got.Jump.User != "jump" {
		t.Errorf("got %+v (jump %+v)", got, got.Jump)
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file should fail")
	}
}
