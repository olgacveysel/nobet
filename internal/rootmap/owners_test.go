package rootmap

import (
	"bytes"
	"strings"
	"testing"
)

func ownersMap() Map {
	return Map{
		Keys: []Key{
			{Fingerprint: "SHA256:alice", Type: "ssh-ed25519", Comments: []string{"alice@laptop"}, Grants: []Grant{
				{Host: "web01", User: "deploy", Routes: []Route{{Via: "sudo ALL, no password"}}},
				{Host: "db01", User: "alice", Routes: []Route{{Via: "sudo ALL, password required", NeedsPassword: true}}},
			}},
			{Fingerprint: "SHA256:ci", Type: "ssh-ed25519", Comments: []string{"gitlab-runner"}, Grants: []Grant{
				{Host: "web01", User: "deploy", Routes: []Route{{Via: "sudo ALL, no password"}}},
				{Host: "web02", User: "alice", Routes: []Route{{Via: "docker group"}}},
			}},
			{Fingerprint: "SHA256:old", Type: "ssh-rsa", Grants: []Grant{{Host: "db01", User: "root", Routes: []Route{{Via: "UID 0 login"}}}}},
		},
		KeylessUsers: []Account{{Host: "db02", User: "alice", Routes: []Route{{Via: "sudo ALL, password required"}}}, {Host: "db02", User: "bob"}},
		Gaps:         []Gap{},
	}
}

func TestOwners(t *testing.T) {
	m := ownersMap()
	if m.Unclaimed() != nil {
		t.Error("without a keys file nothing is unclaimed")
	}
	owners := map[string]string{"SHA256:alice": "alice", "SHA256:ci": "ci"}
	m.SetOwners("/etc/nobet/keys", func(fp string) string { return owners[fp] })
	if u := m.Unclaimed(); len(u) != 1 || u[0].Fingerprint != "SHA256:old" {
		t.Errorf("unclaimed = %+v", u)
	}
	var b bytes.Buffer
	m.WriteText(&b)
	for _, want := range []string{
		"1 key(s) with root access have no owner in /etc/nobet/keys.",
		"\nalice  SHA256:alice  ed25519  alice@laptop\n",
		"\n(no known owner)  SHA256:old  rsa\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("text lacks %q:\n%s", want, b.String())
		}
	}
}

func TestWho(t *testing.T) {
	m := ownersMap()
	m.SetOwners("/etc/nobet/keys", func(fp string) string { return map[string]string{"SHA256:alice": "alice", "SHA256:ci": "ci"}[fp] })
	w := m.Who("alice")
	// Her own key with all its grants, the CI key only where it reaches an
	// account named alice, and her account without key access.
	if len(w.Keys) != 2 || w.Keys[0].Fingerprint != "SHA256:alice" || len(w.Keys[0].Grants) != 2 ||
		w.Keys[1].Fingerprint != "SHA256:ci" || len(w.Keys[1].Grants) != 1 || w.Keys[1].Grants[0].Host != "web02" {
		t.Errorf("keys = %+v", w.Keys)
	}
	if len(w.KeylessUsers) != 1 || w.KeylessUsers[0].Host != "db02" {
		t.Errorf("accounts = %+v", w.KeylessUsers)
	}
	if len(m.Keys[1].Grants) != 2 {
		t.Error("Who changed the original map")
	}

	// Without a keys file, key comments stand in.
	if w := ownersMap().Who("ALICE"); len(w.Keys) != 1 || w.Keys[0].Fingerprint != "SHA256:alice" {
		t.Errorf("by comment: %+v", w.Keys)
	}
	if w := ownersMap().Who("nobody"); len(w.Keys) != 0 || len(w.KeylessUsers) != 0 {
		t.Errorf("nobody: %+v", w)
	}
}
