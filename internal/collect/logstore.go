package collect

import (
	"strconv"
	"strings"
	"time"
)

// LogStore says how long the host can keep its logs: where the journal
// is stored, and how old the system is.
type LogStore struct {
	Journal string    `json:"journal,omitempty"` // persistent, volatile, unknown, or "" without systemd's journal
	Born    time.Time `json:"born,omitzero"`     // when this system was set up, as far as can be told (logStoreScript)
	Booted  time.Time `json:"booted,omitzero"`
}

// logStoreScript finds the journal's files (on disk in /var/log/journal,
// or in memory in /run/log/journal), the boot time, and the install time:
// the latest of the root file system's creation time (where stat can tell
// it), when /etc/machine-id was written and when the basesystem package was
// installed (RPM). A cloud VM's file system and packages date from its
// image, often months before the VM existed; its machine-id is written at
// its own first boot, since images ship it empty.
const logStoreScript = `if command -v journalctl >/dev/null 2>&1; then
  if ls /var/log/journal/*/system*.journal >/dev/null 2>&1; then echo journal=persistent
  elif ls /run/log/journal/*/system*.journal >/dev/null 2>&1; then echo journal=volatile
  else echo journal=unknown
  fi
fi
echo "booted=$(awk '$1 == "btime" { print $2 }' /proc/stat 2>/dev/null)"
born=0
for t in $(stat -c %W / 2>/dev/null) $(stat -c %Y /etc/machine-id 2>/dev/null) $(command -v rpm >/dev/null 2>&1 && rpm -q --qf '%{INSTALLTIME}' basesystem 2>/dev/null); do
  case $t in *[!0-9]*) continue ;; esac
  [ "$t" -gt "$born" ] && born=$t
done
[ "$born" -gt 0 ] || born=
echo "born=$born"
echo done
`

// parseLogStore reads logStoreScript output; nil if it stopped early.
func parseLogStore(s string) *LogStore {
	ls, done := &LogStore{}, false
	epoch := func(v string) time.Time {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return time.Unix(n, 0).UTC()
		}
		return time.Time{}
	}
	for _, line := range lines(s) {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "journal":
			ls.Journal = v
		case "booted":
			ls.Booted = epoch(v)
		case "born":
			ls.Born = epoch(v)
		case "done":
			done = true
		}
	}
	if !done {
		return nil
	}
	return ls
}
