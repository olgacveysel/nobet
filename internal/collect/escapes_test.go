package collect

import (
	"reflect"
	"testing"
)

func TestEscapes(t *testing.T) {
	cases := []struct {
		e    SudoEntry
		want []string
	}{
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/bin/vim /etc/nginx/nginx.conf"}}, []string{"/usr/bin/vim /etc/nginx/nginx.conf"}},
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/bin/systemctl restart nginx", "/usr/bin/systemctl"}}, []string{"/usr/bin/systemctl"}},
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/bin/find /var/log -name *.gz"}}, []string{"/usr/bin/find /var/log -name *.gz"}},
		{SudoEntry{RunAs: "ALL : ALL", Commands: []string{"/usr/bin/python3.12"}}, []string{"/usr/bin/python3.12"}},
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/bin/tee /etc/motd"}}, nil},
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/bin/tee"}}, []string{"/usr/bin/tee"}},
		{SudoEntry{RunAs: "root", Commands: []string{`/usr/bin/git ""`}}, nil},
		{SudoEntry{RunAs: "root", Commands: []string{"/opt/bin/*"}}, []string{"/opt/bin/*"}},
		{SudoEntry{RunAs: "root", Commands: []string{"sudoedit /etc/hosts"}}, nil},
		{SudoEntry{RunAs: "root", Commands: []string{"ALL", "!/bin/bash"}}, nil}, // RootAll covers it
		{SudoEntry{RunAs: "postgres", Commands: []string{"/bin/bash"}}, nil},     // not root
		{SudoEntry{RunAs: "root", NoExec: true, Commands: []string{"/usr/bin/less /var/log/syslog", "/bin/cp"}}, []string{"/bin/cp"}},
		{SudoEntry{RunAs: "root", Commands: []string{"/usr/sbin/reboot", "/usr/bin/apt-get update"}}, nil},
	}
	for _, c := range cases {
		if got := c.e.Escapes(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v: got %q, want %q", c.e, got, c.want)
		}
	}
}

func TestParseSudoEntryTags(t *testing.T) {
	e, ok := parseSudoEntry("(root) NOPASSWD: NOEXEC: /usr/bin/less /var/log/syslog, /usr/bin/journalctl")
	if !ok || !e.NoPasswd || !e.NoExec || len(e.Commands) != 2 {
		t.Errorf("got %+v", e)
	}
	e, _ = parseSudoEntry("(root) NOEXEC: EXEC: PASSWD: /usr/bin/vim")
	if e.NoPasswd || e.NoExec || e.Commands[0] != "/usr/bin/vim" {
		t.Errorf("got %+v", e)
	}
}
