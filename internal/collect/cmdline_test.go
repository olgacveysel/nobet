package collect

import (
	"reflect"
	"testing"
)

func TestCommandPaths(t *testing.T) {
	cases := []struct {
		line     string
		unquoted bool
		want     []string
	}{
		// Debian /etc/crontab and cron.d lines (command part).
		{`cd / && run-parts --report /etc/cron.hourly`, false, nil},
		{`test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }`, false, nil},
		{`[ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi`, false, []string{"/usr/lib/php/sessionclean"}},
		{`/home/deploy/backup.sh > /dev/null 2>&1`, false, []string{"/home/deploy/backup.sh"}},
		{`/usr/bin/php /var/www/app/artisan schedule:run >> /var/log/app.log 2>&1`, false, []string{"/usr/bin/php", "/var/www/app/artisan"}},
		{`/usr/bin/flock -n /run/job.lock /opt/app/bin/job --quiet`, false, []string{"/usr/bin/flock", "/opt/app/bin/job"}},
		{`nice -n 19 ionice -c3 /usr/local/bin/reindex`, false, []string{"/usr/local/bin/reindex"}},
		{`timeout -s KILL 1h /opt/x/run`, false, []string{"/opt/x/run"}},
		{`PATH=/opt/tools/bin:$PATH LANG=C /opt/tools/bin/sync`, false, []string{"/opt/tools/bin/sync"}},
		{`env -i HOME=/root /usr/bin/python3 -u /srv/jobs/clean.py --dry-run`, false, []string{"/usr/bin/python3", "/srv/jobs/clean.py"}},
		{`cd /opt/app && ./bin/refresh.sh`, false, []string{"/opt/app/bin/refresh.sh"}},
		{`/bin/sh -c '/opt/a.sh; /opt/b.sh'`, false, []string{"/bin/sh", "/opt/a.sh", "/opt/b.sh"}},
		{`bash /root/scripts/rotate.sh`, false, []string{"/root/scripts/rotate.sh"}},
		// Runs as someone else: not a root route.
		{`sudo -u www-data /usr/bin/php /var/www/x/cron.php`, false, nil},
		{`su - app -c "/opt/app/run.sh"`, false, nil},
		{`/usr/sbin/runuser -u app -- /opt/app/run.sh; /opt/after.sh`, false, []string{"/opt/after.sh"}},
		// Redirection targets are no programs.
		{`echo hi >/tmp/out; cat < /etc/hosts`, false, nil},
		// systemctl prints argv without its quotes.
		{`/bin/sh -c exec /opt/app/start.sh --port 80`, true, []string{"/bin/sh", "/opt/app/start.sh"}},
		{`/usr/sbin/sshd -D $SSHD_OPTS`, true, []string{"/usr/sbin/sshd"}},
	}
	for _, c := range cases {
		if got := CommandPaths(c.line, c.unquoted); !reflect.DeepEqual(got, c.want) {
			t.Errorf("CommandPaths(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestCronJob(t *testing.T) {
	// Debian's /etc/crontab with a root job and another user's job added.
	crontab := `# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
*/5 * * * *	root	/opt/backup/run.sh --full % mail body
@reboot	root	/home/ops/on-boot.sh
0 1 * * *	deploy	/home/deploy/not-root.sh
`
	j := cronJob("/etc/crontab", "system", lines(crontab))
	want := []string{"/etc/crontab", "/bin/sh", "/usr/local/sbin", "/usr/local/bin", "/sbin", "/bin", "/usr/sbin", "/usr/bin", "/opt/backup/run.sh", "/home/ops/on-boot.sh"}
	if j.Kind != "cron" || j.Source != "/etc/crontab" || !reflect.DeepEqual(j.Paths, want) {
		t.Errorf("got %+v\nwant paths %q", j, want)
	}

	root := cronJob("/var/spool/cron/crontabs/root", "user", lines("MAILTO=ops\n0 2 * * * /root/backup.sh >/dev/null 2>&1\n@daily /usr/local/bin/prune\n"))
	if want := []string{"/var/spool/cron/crontabs/root", "/root/backup.sh", "/usr/local/bin/prune"}; !reflect.DeepEqual(root.Paths, want) {
		t.Errorf("root crontab: got %q, want %q", root.Paths, want)
	}

	ana := cronJob("/etc/anacrontab", "anacron", lines("SHELL=/bin/sh\n1\t5\tcron.daily\trun-parts --report /etc/cron.daily\n@monthly 15 local.monthly /opt/monthly.sh\n"))
	if want := []string{"/etc/anacrontab", "/bin/sh", "/opt/monthly.sh"}; !reflect.DeepEqual(ana.Paths, want) {
		t.Errorf("anacrontab: got %q, want %q", ana.Paths, want)
	}
}

func TestSystemdJobs(t *testing.T) {
	// systemctl show output (systemd 255), trimmed to the properties asked for.
	out := `Id=cron.service
User=
DynamicUser=no
FragmentPath=/usr/lib/systemd/system/cron.service
DropInPaths=
ExecStart={ path=/usr/sbin/cron ; argv[]=/usr/sbin/cron -f -P $EXTRA_OPTS ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=app.service
User=root
DynamicUser=no
FragmentPath=/etc/systemd/system/app.service
DropInPaths=/etc/systemd/system/app.service.d/override.conf
ExecStartPre={ path=/bin/sh ; argv[]=/bin/sh -c /opt/app/migrate.sh ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStart={ path=/opt/app/bin/server ; argv[]=/opt/app/bin/server --config /etc/app.yml ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecReload={ path=/bin/kill ; argv[]=/bin/kill -HUP $MAINPID ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=postgresql@16-main.service
User=postgres
DynamicUser=no
FragmentPath=/usr/lib/systemd/system/postgresql@.service
ExecStart={ path=/usr/bin/pg_ctlcluster ; argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=systemd-resolved.service
User=
DynamicUser=yes
ExecStart={ path=/usr/lib/systemd/systemd-resolved ; argv[]=/usr/lib/systemd/systemd-resolved ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=man-db.service
User=man
DynamicUser=no
FragmentPath=/usr/lib/systemd/system/man-db.service
ExecStart={ path=/usr/bin/install ; argv[]=/usr/bin/install -d -o man -g man -m 0755 /var/cache/man ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStart={ path=/usr/bin/mandb ; argv[]=/usr/bin/mandb --quiet ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStartEx={ path=/usr/bin/install ; argv[]=/usr/bin/install -d -o man -g man -m 0755 /var/cache/man ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStartEx={ path=/usr/bin/mandb ; argv[]=/usr/bin/mandb --quiet ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
ExecStartPreEx={ path=/opt/hook ; argv[]=/opt/hook now ; flags=ignore-failure no-setuid ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=multi.service
User=
DynamicUser=no
FragmentPath=/etc/systemd/system/multi.service
ExecStart={ path=/usr/bin/true ; argv[]=/usr/bin/true ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 } ; { path=/opt/second ; argv[]=/opt/second now ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }

Id=console-getty.service
LoadState=masked
User=
FragmentPath=/etc/systemd/system/console-getty.service
`
	got := systemdJobs(splitRaw(out))
	want := []RootJob{
		{Kind: "systemd", Source: "cron.service", Paths: []string{"/usr/lib/systemd/system/cron.service", "/usr/sbin/cron"}},
		{Kind: "systemd", Source: "app.service", Paths: []string{"/etc/systemd/system/app.service", "/etc/systemd/system/app.service.d/override.conf", "/bin/sh", "/opt/app/migrate.sh", "/opt/app/bin/server", "/bin/kill"}},
		{Kind: "systemd-privileged", Source: "man-db.service", Paths: []string{"/opt/hook", "/usr/bin/install"}}, // + and ! commands only; not mandb
		{Kind: "systemd", Source: "multi.service", Paths: []string{"/etc/systemd/system/multi.service", "/usr/bin/true", "/opt/second"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

// splitRaw keeps blank lines, which separate systemctl show blocks.
func splitRaw(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestSudoJobs(t *testing.T) {
	f := &Facts{SudoRights: map[string][]SudoEntry{
		"deploy": {{RunAs: "root", NoPasswd: true, Commands: []string{"/home/deploy/release.sh", "/usr/bin/systemctl restart app", "/opt/tools/*", "!/usr/bin/su"}}},
		"admin":  {{RunAs: "ALL : ALL", Commands: []string{"ALL"}}},
		"web":    {{RunAs: "www-data", NoPasswd: true, Commands: []string{"/var/www/run.sh"}}},
	}}
	want := []RootJob{{Kind: "sudo", Source: "sudo rule for deploy", Paths: []string{"/home/deploy/release.sh", "/usr/bin/systemctl", "/opt/tools"}}}
	if got := sudoJobs(f); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
