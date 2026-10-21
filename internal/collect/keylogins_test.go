package collect

import (
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestKeyLoginsScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
	dir := t.TempDir()
	bin, logs := filepath.Join(dir, "bin"), filepath.Join(dir, "log")
	for _, d := range []string{bin, logs} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	gz := func(path, content string) {
		t.Helper()
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		w.Write([]byte(content))
		w.Close()
		write(path, b.String(), 0o640)
	}

	// The host's clock and zone, and a journal that only answers when asked
	// for root's sshd processes; with pattern matching (-g) unless NOGREP
	// is set, as when journalctl is built without it.
	write(filepath.Join(bin, "date"), "#!/bin/sh\ncase \"$1\" in\n+%s) echo 1792584000 ;;\n+%z) echo +0200 ;;\n+%Y) echo 2026 ;;\nesac\n", 0o755)
	journal := filepath.Join(dir, "journal")
	write(filepath.Join(bin, "journalctl"), `#!/bin/sh
case "$*" in
*'-n 0 -g ('*) [ -n "$NOGREP" ] && echo "journalctl: invalid option -- 'g'" >&2 || echo 'Bad pattern "(": missing closing parenthesis' >&2; exit 1 ;;
*'-n 0'*) ;;
*'_UID=0 _COMM=sshd _COMM=sshd-session -g Accepted publickey for '*) [ -z "$NOGREP" ] && grep -F 'Accepted publickey for ' `+journal+` ;;
*'_UID=0 _COMM=sshd _COMM=sshd-session') cat `+journal+` ;;
*) exit 1 ;;
esac
`, 0o755)
	write(journal, strings.Join([]string{
		"1790000000.000001 web01 sshd[100]: Server listening on 0.0.0.0 port 22.",
		"1791000000.123456 web01 sshd-session[200]: Accepted publickey for root from 10.0.0.5 port 50000 ssh2: ED25519 SHA256:aaaa",
		"1792000000.5 web01 sshd-session[201]: Accepted publickey for deploy from 10.0.0.6 port 50001 ssh2: RSA SHA256:bbbb",
		"1792100000 web01 sshd-session[202]: Accepted publickey for root from 10.0.0.7 port 50002 ssh2: ED25519-CERT SHA256:cccc ID alice (serial 7) CA ED25519 SHA256:dddd",
		"1792200000.0 web01 sshd-session[203]: Accepted password for alice from 10.0.0.8 port 50003 ssh2",
	}, "\n")+"\n", 0o644)

	// rsyslog's precise format. The deploy login falls in the journal's
	// time, where the journal (which has an older one) is trusted instead.
	write(filepath.Join(logs, "auth.log"), strings.Join([]string{
		"2026-10-01T08:00:00.000000+02:00 web01 sshd[300]: Server listening on :: port 22.",
		"2026-10-20T09:00:00.000000+02:00 web01 sshd-session[301]: Accepted publickey for deploy from 10.0.0.6 port 50010 ssh2: RSA SHA256:bbbb",
		"2026-10-20T09:00:01.000000+02:00 web01 sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/true",
	}, "\n")+"\n", 0o640)
	// Classic syslog lines, from before the journal begins: no year, the
	// host's zone; December is last year's.
	gz(filepath.Join(logs, "auth.log.2.gz"), "Jun  3 07:00:00 web01 sshd[399]: Server listening on 0.0.0.0 port 22.\n"+
		"Jun 15 10:00:00 web01 sshd[400]: Accepted publickey for backup from 10.0.0.9 port 50020 ssh2: ED25519 SHA256:eeee\n")
	gz(filepath.Join(logs, "auth.log.3.gz"), "Dec 30 23:00:00 web01 sshd[500]: Accepted publickey for root from 10.0.0.1 port 50030 ssh2: ED25519 SHA256:ffff\n")
	write(filepath.Join(logs, "auth.log.4.xz"), "", 0o640)
	// No sshd messages: not a source, so it does not stretch Since.
	write(filepath.Join(logs, "messages"), "Jan  2 10:00:00 web01 kernel: booting\n", 0o640)

	at := func(y int, m time.Month, d, h int) time.Time { return time.Date(y, m, d, h, 0, 0, 0, time.UTC) }
	want := &KeyLogins{
		Checked: now,
		Since:   at(2025, 12, 30, 21),
		Sources: []string{"journal", logs + "/auth.log", logs + "/auth.log.2.gz", logs + "/auth.log.3.gz"},
		Last: map[string]time.Time{
			"root SHA256:aaaa":   time.Unix(1791000000, 0).UTC(),
			"deploy SHA256:bbbb": time.Unix(1792000000, 0).UTC(),
			"root SHA256:cccc":   time.Unix(1792100000, 0).UTC(),
			"root SHA256:dddd":   time.Unix(1792100000, 0).UTC(), // the certificate's CA
			"backup SHA256:eeee": at(2026, 6, 15, 8),
			"root SHA256:ffff":   at(2025, 12, 30, 21),
		},
	}
	script := strings.ReplaceAll(keyLoginsScript, "/var/log/", logs+"/")
	for _, nogrep := range []string{"", "1"} {
		cmd := exec.Command("/bin/sh", "-c", script)
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "NOGREP="+nogrep)
		out, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "10.0.0.") {
			t.Errorf("client addresses left the host:\n%s", out)
		}
		got := parseKeyLogins(string(out))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("NOGREP=%q:\ngot  %+v\nwant %+v\noutput:\n%s", nogrep, got, want, out)
		}
		// Without the final marker the output is incomplete.
		if parseKeyLogins(strings.TrimSuffix(string(out), "done\n")) != nil {
			t.Error("output without done parsed")
		}
	}
	if last, ok := want.LastLogin("deploy", "SHA256:bbbb"); !ok || !last.Equal(time.Unix(1792000000, 0)) {
		t.Errorf("LastLogin(deploy) = %v, %v", last, ok)
	}
}

func TestLogTime(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	utc2 := zone("+0200")
	cases := map[string]time.Time{
		"1767355200":                  now,
		"1767355200.25":               now,
		"2026-01-02T14:00:00+02:00":   now,
		"2026-01-02T14:00:00.5+02:00": now.Add(500 * time.Millisecond),
		"2026-01-02T14:00:00+0200":    now,                                            // journalctl -o short-iso
		"Jan 2 14:00:00":              now,                                            // host zone +0200
		"Jan 3 13:00:00":              now.Add(23 * time.Hour),                        // a clock slightly behind the log
		"Dec 31 14:00:00":             time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC), // last year
	}
	for in, want := range cases {
		if got, ok := logTime(in, now, 2026, utc2); !ok || !got.Equal(want) {
			t.Errorf("logTime(%q) = %v, %v; want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "12x", "1767355200.x", "2026-13-01T00:00:00Z", "Foo 2 14:00:00"} {
		if _, ok := logTime(bad, now, 2026, utc2); ok {
			t.Errorf("logTime(%q) should fail", bad)
		}
	}
}
