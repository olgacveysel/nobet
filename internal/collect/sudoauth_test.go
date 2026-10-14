package collect

import (
	"reflect"
	"testing"
)

// Real `sudo -l -U` output from openSUSE Leap 15.6, whose default sudoers
// has "Defaults targetpw" and "ALL ALL=(ALL) ALL", plus two hand-made
// users: one with "Defaults:ci !authenticate" and one with per-command
// Defaults, which are not evaluated.
const suseSudo = `@@user alice
Matching Defaults entries for alice on 6b264663cc61:
    always_set_home, env_reset, env_keep="LANG LC_ADDRESS LC_CTYPE LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS XDG_SESSION_COOKIE", !insults, secure_path=/usr/sbin\:/usr/bin\:/sbin\:/bin, targetpw

User alice may run the following commands on 6b264663cc61:
    (ALL) ALL
@@user ci
Matching Defaults entries for ci on 6b264663cc61:
    env_reset, targetpw, !authenticate

User ci may run the following commands on 6b264663cc61:
    (ALL) ALL
@@user bob
Matching Defaults entries for bob on 6b264663cc61:
    env_reset, rootpw, !rootpw

Runas and Command-specific defaults for bob:
    Defaults!/usr/bin/vim rootpw

User bob may run the following commands on 6b264663cc61:
    (ALL) ALL
@@user nobody
User nobody is not allowed to run sudo on 6b264663cc61.
`

func TestParseSudoRightsDefaults(t *testing.T) {
	rights, defs := parseSudoRights(suseSudo)
	for _, u := range []string{"alice", "ci", "bob"} {
		if e := rights[u]; len(e) != 1 || !e[0].RootAll() {
			t.Errorf("%s: %+v", u, e)
		}
	}
	f := &Facts{SudoDefaults: defs}
	for user, want := range map[string]string{"alice": SudoAuthTarget, "ci": SudoAuthNone, "bob": SudoAuthUser, "nobody": SudoAuthUser} {
		if got := f.SudoAuthFor(user, "root", "ALL"); got != want {
			t.Errorf("SudoAuthFor(%s) = %q, want %q", user, got, want)
		}
	}
	// bob's per-command Defaults!/usr/bin/vim rootpw applies to vim only.
	if got := f.SudoAuthFor("bob", "root", "/usr/bin/vim /etc/hosts"); got != SudoAuthTarget {
		t.Errorf("bob running vim: %q", got)
	}
}

// Real `sudo -l -U` output from sudo 1.9.15 (Ubuntu 24.04) for:
//
//	Cmnd_Alias EDITORS = /usr/bin/vim, /usr/bin/nano
//	Defaults!EDITORS rootpw
//	Defaults!/usr/bin/less !authenticate
//	Defaults>root targetpw
//	alice ALL=(root) /usr/bin/vim, /usr/bin/less, /usr/bin/find
//
// Note sudo printing two Defaults entries on one line.
const scopedSudo = `@@user alice
Matching Defaults entries for alice on dbde4cd640c7:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

Runas and Command-specific defaults for alice:
    Defaults>root targetpw    Defaults!/usr/bin/vim, /usr/bin/nano rootpw
    Defaults!/usr/bin/less !authenticate

User alice may run the following commands on dbde4cd640c7:
    (root) /usr/bin/vim, /usr/bin/less, /usr/bin/find
`

func TestParseScopedDefaults(t *testing.T) {
	rights, defs := parseSudoRights(scopedSudo)
	if e := rights["alice"]; len(e) != 1 || len(e[0].Commands) != 3 {
		t.Fatalf("rules: %+v", e)
	}
	want := []ScopedDefault{
		{Kind: ">", List: []string{"root"}, Flags: map[string]bool{"targetpw": true}},
		{Kind: "!", List: []string{"/usr/bin/vim", "/usr/bin/nano"}, Flags: map[string]bool{"rootpw": true}},
		{Kind: "!", List: []string{"/usr/bin/less"}, Flags: map[string]bool{"authenticate": false}},
	}
	if got := defs["alice"].Scoped; !reflect.DeepEqual(got, want) {
		t.Errorf("scoped:\n got %+v\nwant %+v", got, want)
	}
	f := &Facts{SudoDefaults: defs}
	for cmd, want := range map[string]string{
		"/usr/bin/vim":           SudoAuthTarget, // rootpw
		"/usr/bin/less":          SudoAuthNone,   // !authenticate beats targetpw
		"/usr/bin/find":          SudoAuthTarget, // Defaults>root targetpw
		"/usr/bin/less /var/log": SudoAuthNone,   // a command listed without arguments covers any
		"ALL":                    SudoAuthTarget,
	} {
		if got := f.SudoAuthFor("alice", "root", cmd); got != want {
			t.Errorf("SudoAuthFor(alice, %s) = %q, want %q", cmd, got, want)
		}
	}
	if got := f.SudoAuthFor("alice", "postgres", "/usr/bin/find"); got != SudoAuthUser {
		t.Errorf("runas postgres: %q", got)
	}
}

func TestSplitBinding(t *testing.T) {
	cases := []struct {
		body           string
		list, settings []string
	}{
		{"/usr/bin/vim, /usr/bin/nano rootpw", []string{"/usr/bin/vim", "/usr/bin/nano"}, []string{"rootpw"}},
		{"/bin/systemctl status nginx rootpw, !lecture", []string{"/bin/systemctl status nginx"}, []string{"rootpw", "!lecture"}},
		{`root env_keep+="LANG LC_ALL", targetpw`, []string{"root"}, []string{`env_keep+="LANG LC_ALL"`, "targetpw"}},
	}
	for _, c := range cases {
		list, settings, ok := splitBinding(c.body)
		if !ok || !reflect.DeepEqual(list, c.list) || !reflect.DeepEqual(settings, c.settings) {
			t.Errorf("splitBinding(%q) = %q, %q, %v", c.body, list, settings, ok)
		}
	}
}
