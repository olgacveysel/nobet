package collect

import (
	"reflect"
	"testing"
)

// sudoEnvSample is `sudo -l -U` from sudo 1.9.16 (Debian 13) with these
// sudoers lines, and AlmaLinux 9's stock env_keep list for ops:
//
//	Defaults:alice env_keep += "LD_PRELOAD"
//	alice ALL=(root) NOPASSWD: /usr/bin/true
//	bob ALL=(root) SETENV: NOPASSWD: /usr/bin/true, /usr/bin/id
//	Defaults:carol setenv
//	carol ALL=(root) NOPASSWD: /usr/bin/true
//	Defaults:dave env_keep += "PYTHONPATH PERL5LIB"
//	dave ALL=(root) NOPASSWD: /usr/local/bin/pyjob, /usr/bin/true
//	Defaults:erin !env_reset
//	erin ALL=(root) NOPASSWD: /usr/bin/true
//	Defaults!/usr/bin/id env_keep += "LD_PRELOAD"
//	frank ALL=(root) NOPASSWD: /usr/bin/true, /usr/bin/id
const sudoEnvSample = `@@user alice
Matching Defaults entries for alice on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, env_keep+=LD_PRELOAD

Runas and Command-specific defaults for alice:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User alice may run the following commands on 21848a68cee8:
    (root) NOPASSWD: /usr/bin/true
@@user bob
Matching Defaults entries for bob on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

Runas and Command-specific defaults for bob:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User bob may run the following commands on 21848a68cee8:
    (root) SETENV: NOPASSWD: /usr/bin/true, /usr/bin/id
@@user carol
Matching Defaults entries for carol on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, setenv

Runas and Command-specific defaults for carol:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User carol may run the following commands on 21848a68cee8:
    (root) NOPASSWD: /usr/bin/true
@@user dave
Matching Defaults entries for dave on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, env_keep+="PYTHONPATH PERL5LIB"

Runas and Command-specific defaults for dave:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User dave may run the following commands on 21848a68cee8:
    (root) NOPASSWD: /usr/local/bin/pyjob, /usr/bin/true
@@user erin
Matching Defaults entries for erin on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, !env_reset

Runas and Command-specific defaults for erin:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User erin may run the following commands on 21848a68cee8:
    (root) NOPASSWD: /usr/bin/true
@@user frank
Matching Defaults entries for frank on 21848a68cee8:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

Runas and Command-specific defaults for frank:
    Defaults!/usr/bin/id env_keep+=LD_PRELOAD

User frank may run the following commands on 21848a68cee8:
    (root) NOPASSWD: /usr/bin/true, /usr/bin/id
@@user ops
Matching Defaults entries for ops on a596ed0e2b58:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User ops may run the following commands on a596ed0e2b58:
    (root) NOPASSWD: /usr/bin/systemctl restart nginx
`

func TestEnvEscapes(t *testing.T) {
	f := &Facts{Interpreters: map[string]string{"/usr/local/bin/pyjob": "/usr/bin/python3"}}
	f.SudoRights, f.SudoDefaults = parseSudoRights(sudoEnvSample)
	f.markEnvEscapes()
	want := map[string]map[string]string{
		"alice": {"/usr/bin/true": "env_keep keeps LD_PRELOAD"},
		"bob":   {"/usr/bin/true": "SETENV lets the caller set LD_PRELOAD", "/usr/bin/id": "SETENV lets the caller set LD_PRELOAD"},
		"carol": {"/usr/bin/true": "Defaults setenv lets the caller set LD_PRELOAD"},
		"dave":  {"/usr/local/bin/pyjob": "env_keep keeps PYTHONPATH for this python script"},
		"erin":  nil, // !env_reset: sudo still drops LD_*
		"frank": {"/usr/bin/id": "env_keep keeps LD_PRELOAD"},
		"ops":   nil, // RHEL's stock env_keep list
	}
	for u, w := range want {
		if len(f.SudoRights[u]) != 1 {
			t.Fatalf("%s: rules %+v", u, f.SudoRights[u])
		}
		e := f.SudoRights[u][0]
		if got := e.EnvEscapes; !reflect.DeepEqual(got, w) {
			t.Errorf("%s: %q, want %q", u, got, w)
		}
		var esc []string
		for c := range w {
			esc = append(esc, c)
		}
		if len(e.Escapes()) != len(esc) {
			t.Errorf("%s: Escapes() = %q", u, e.Escapes())
		}
	}
	if !f.SudoRights["bob"][0].SetEnv || f.SudoRights["alice"][0].SetEnv {
		t.Error("SETENV tag")
	}
	// env_keep -= takes it back; env_keep= replaces the list.
	for _, c := range []struct {
		settings []string
		want     bool
	}{
		{[]string{`env_keep+=LD_PRELOAD`, `env_keep-=LD_PRELOAD`}, false},
		{[]string{`env_keep+=LD_PRELOAD`, `env_keep="LANG PS1"`}, false},
		{[]string{`env_keep="LANG LD_PRELOAD"`}, true},
	} {
		if got := readFlags(c.settings)["env_keep:LD_PRELOAD"]; got != c.want {
			t.Errorf("%q: %v", c.settings, got)
		}
	}
}
