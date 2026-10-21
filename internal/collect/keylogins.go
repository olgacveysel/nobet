package collect

import (
	"strconv"
	"strings"
	"time"
)

// KeyLogins says when authorized keys last logged in, from sshd's
// "Accepted publickey" log messages. A key missing from Last did not log in
// at any time since Since, as far as the logs tell.
type KeyLogins struct {
	Checked time.Time            `json:"checked"`        // the host's clock when the logs were read
	Since   time.Time            `json:"since,omitzero"` // the oldest sshd message read; zero if none was found
	Sources []string             `json:"sources,omitempty"`
	Last    map[string]time.Time `json:"last,omitempty"` // "user SHA256:..." -> the newest login with that key
}

// LastLogin returns when user last logged in with the key.
func (k *KeyLogins) LastLogin(user, fingerprint string) (time.Time, bool) {
	t, ok := k.Last[user+" "+fingerprint]
	return t, ok
}

// keyLoginsScript reads sshd's login messages from the journal and from
// the syslog files (with their rotated and gzipped copies), and prints,
// per source, the time of its oldest sshd message and the newest login
// per account and key. Only times, account names and key fingerprints
// leave the host. For a certificate login, the CA's fingerprint counts as
// used too (a cert-authority line in authorized_keys).
//
// Journal entries are only taken from root's sshd processes (_UID=0 and
// _COMM): any account can write a message that claims to be sshd's with
// logger, but not with those fields. Syslog files cannot tell the two
// apart; parseKeyLogins only uses them for the time before the journal
// begins.
//
// A server under attack logs millions of failed logins, so the logins are
// picked out first (journalctl -g where it has pattern matching, grep -F
// otherwise) and only the oldest sshd message is read besides them.
const keyLoginsScript = `echo "now=$(date +%s) tz=$(date +%z) year=$(date +%Y)"
stamp='{ ts = ($1 ~ /^[0-9][0-9][0-9][0-9]-/ || $1 ~ /^[0-9]+([.][0-9]+)?$/) ? $1 : $1 " " $2 " " $3 }'
first="$stamp"'
{ print "src=" src "|" ts; exit }'
logins="$stamp"'
/ Accepted publickey for / {
	i = 1
	while (i < NF && $i != "Accepted") i++
	user = $(i + 3)
	j = i
	while (j < NF && $j != "ssh2:") j++
	if ($(j + 2) ~ /^SHA256:/) last[user "|" $(j + 2)] = ts
	if ($(j + 1) ~ /-CERT$/)
		for (k = j; k < NF; k++)
			if ($k == "CA" && $(k + 2) ~ /^SHA256:/) last[user "|" $(k + 2)] = ts
}
END { for (k in last) print "use=" src "|" last[k] "|" k }'
if command -v journalctl >/dev/null 2>&1; then
	# short-unix needs systemd 233; CentOS 7 has short-iso.
	fmt=short-unix
	journalctl -q --no-pager -o short-unix -n 0 >/dev/null 2>&1 || fmt=short-iso
	set -- -q --no-pager -o $fmt _UID=0 _COMM=sshd _COMM=sshd-session
	journalctl "$@" 2>/dev/null | awk -v src=journal "$first"
	# -g exits 1 when nothing matches; only a build with pattern matching
	# calls "(" a bad pattern.
	if journalctl -q --no-pager -n 0 -g '(' 2>&1 | grep -q 'Bad pattern'; then
		journalctl "$@" -g 'Accepted publickey for ' 2>/dev/null
	else
		journalctl "$@" 2>/dev/null | grep -F 'Accepted publickey for '
	fi | awk -v src=journal "$logins"
fi
readlog() {
	case $1 in
	*.gz) gzip -dc "$1" ;;
	*) cat "$1" ;;
	esac 2>/dev/null
}
for f in /var/log/auth.log* /var/log/secure* /var/log/messages*; do
	[ -f "$f" ] || continue
	case $f in
	*.xz | *.bz2 | *.zst | *.lz4) echo "unread=$f"; continue ;;
	esac
	readlog "$f" | grep -m 1 -F -e 'sshd[' -e 'sshd-session[' | awk -v src="$f" "$first"
	readlog "$f" | grep -F 'Accepted publickey for ' | grep -F -e 'sshd[' -e 'sshd-session[' | awk -v src="$f" "$logins"
done
echo done
`

// parseKeyLogins reads keyLoginsScript output; nil if it stopped early.
func parseKeyLogins(s string) *KeyLogins {
	var (
		kl      KeyLogins
		loc     *time.Location
		year    int
		done    bool
		journal time.Time // when the journal's sshd messages begin
	)
	type use struct {
		src  string
		at   time.Time
		user string
		fp   string
	}
	var uses []use
	firsts := map[string]time.Time{}
	var order []string
	for _, line := range lines(s) {
		switch {
		case strings.HasPrefix(line, "now="):
			kv := parseFields(line)
			sec, err := strconv.ParseInt(kv["now"], 10, 64)
			if err != nil {
				return nil
			}
			kl.Checked = time.Unix(sec, 0).UTC()
			year, _ = strconv.Atoi(kv["year"])
			loc = zone(kv["tz"])
		case loc == nil:
			return nil
		case strings.HasPrefix(line, "src="):
			src, ts, _ := strings.Cut(strings.TrimPrefix(line, "src="), "|")
			if t, ok := logTime(ts, kl.Checked, year, loc); ok {
				if _, seen := firsts[src]; !seen {
					order = append(order, src)
				}
				firsts[src] = t
			}
		case strings.HasPrefix(line, "use="):
			p := strings.Split(strings.TrimPrefix(line, "use="), "|")
			if len(p) != 4 || !safeUser.MatchString(p[2]) || !strings.HasPrefix(p[3], "SHA256:") {
				continue
			}
			if t, ok := logTime(p[1], kl.Checked, year, loc); ok {
				uses = append(uses, use{p[0], t, p[2], p[3]})
			}
		case line == "done":
			done = true
		}
	}
	if !done {
		return nil
	}
	if t, ok := firsts["journal"]; ok {
		journal = t
	}
	for _, src := range order {
		kl.Sources = append(kl.Sources, src)
		if t := firsts[src]; kl.Since.IsZero() || t.Before(kl.Since) {
			kl.Since = t
		}
	}
	for _, u := range uses {
		if u.src != "journal" && !journal.IsZero() && !u.at.Before(journal) {
			continue // the journal covers this time, and it can be trusted
		}
		if kl.Last == nil {
			kl.Last = map[string]time.Time{}
		}
		k := u.user + " " + u.fp
		if u.at.After(kl.Last[k]) {
			kl.Last[k] = u.at
		}
	}
	return &kl
}

// parseFields splits "a=1 b=2" into a map.
func parseFields(line string) map[string]string {
	m := map[string]string{}
	for _, f := range strings.Fields(line) {
		if k, v, ok := strings.Cut(f, "="); ok {
			m[k] = v
		}
	}
	return m
}

// zone turns date's %z (+0200) into a fixed zone; UTC if it is unreadable.
func zone(z string) *time.Location {
	if len(z) != 5 || (z[0] != '+' && z[0] != '-') {
		return time.UTC
	}
	h, err1 := strconv.Atoi(z[1:3])
	m, err2 := strconv.Atoi(z[3:])
	if err1 != nil || err2 != nil {
		return time.UTC
	}
	off := (h*60 + m) * 60
	if z[0] == '-' {
		off = -off
	}
	return time.FixedZone(z, off)
}

// logTime reads the timestamps keyLoginsScript passes on: the journal's
// seconds since 1970 (or short-iso), RFC 3339 from rsyslog's precise format, or the
// classic syslog "Oct  2 13:49:06", which has no year or zone: the host's
// zone, and the year that puts it at most a day after the host's clock.
func logTime(s string, now time.Time, year int, loc *time.Location) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	if s[0] >= '0' && s[0] <= '9' {
		if sec, frac, _ := strings.Cut(s, "."); !strings.Contains(s, "-") {
			n, err := strconv.ParseInt(sec, 10, 64)
			if err != nil || (frac != "" && strings.Trim(frac, "0123456789") != "") {
				return time.Time{}, false
			}
			return time.Unix(n, 0).UTC(), true
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil { // journalctl -o short-iso
			t, err = time.Parse("2006-01-02T15:04:05-0700", s)
		}
		return t.UTC(), err == nil
	}
	t, err := time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(s), " "), loc)
	if err != nil || year == 0 {
		return time.Time{}, false
	}
	t = t.AddDate(year, 0, 0)
	if t.After(now.Add(24 * time.Hour)) {
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC(), true
}
