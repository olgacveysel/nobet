package collect

// Collector scripts. They run under POSIX sh on the target, are read-only,
// and print simple line-based output that the parsers in collect.go read.
// Some distros keep sshd, ss and sudo in sbin, which is not on a
// non-login PATH, hence the PATH line.

// Defines sshd_opts, which prints the -o options the running sshd was
// started with, one per line, for every sshd -T to use. RHEL 8 and its
// rebuilds pass the system crypto policy that way (ExecStart=/usr/sbin/sshd
// -D $OPTIONS $CRYPTO_POLICY), so sshd -T without them shows OpenSSH's
// built-in algorithms instead of the ones in effect. The command line is
// NUL-separated, or one string in the listener's process title on newer
// OpenSSH ("sshd: /usr/sbin/sshd -oX=y [listener] ...").
const sshdOptsFunc = `sshd_opts_from() {
  tr '\0 ' '\n\n' < "$1" | awk '$0 == "-o" { if ((getline v) > 0) print "-o" v; next } /^-o[A-Za-z]+=/ { print }'
}
sshd_opts() {
  pid=$(cat /run/sshd.pid /var/run/sshd.pid 2>/dev/null | head -n 1)
  case "$pid" in ''|*[!0-9]*) return 0 ;; esac
  [ -r "/proc/$pid/cmdline" ] && sshd_opts_from "/proc/$pid/cmdline"
  return 0
}
`

// Prints sshd's effective config for an arbitrary account connecting from
// TEST-NET-1, then "@@match" and the Match lines of the config files.
// Plain sshd -T is only the fallback for old sshd versions: it fails
// outright on configs with "Match LocalPort". Prints nothing (and succeeds)
// when sshd is not installed at all.
const sshdScript = `PATH=$PATH:/usr/sbin:/sbin
command -v sshd >/dev/null 2>&1 || exit 0
` + sshdOptsFunc + `opts=$(sshd_opts)
set -f # $opts is split into options, never globbed
probe() { sshd -T -C "user=nobet-probe,host=nobet.invalid,addr=192.0.2.1,laddr=192.0.2.2,lport=$1" $opts 2>/dev/null; }
if out=$(probe 22); then
  port=$(printf '%s\n' "$out" | awk '$1=="port" {print $2; exit}')
  if [ -n "$port" ] && [ "$port" != 22 ]; then out=$(probe "$port") || exit 1; fi
else
  out=$(sshd -T $opts) || exit 1
fi
set +f
printf '%s\n' "$out"
echo "@@match"
for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf /usr/etc/ssh/sshd_config /usr/etc/ssh/sshd_config.d/*.conf; do
  [ -f "$f" ] && grep -iE '^[[:space:]]*match[[:space:]]' "$f"
done
true
`

// Prints each sudoers file prefixed with its path, so findings can say where a rule lives.
const sudoersScript = `for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] && sed "s|^|$f: |" "$f"
done
true
`

// Lists listening sockets with ss. Without ss, or with one too old for -H,
// it prints "@@proc <arch>" and the raw kernel tables instead: protocol,
// local address and state, with addresses in the host's byte order.
const listenersScript = `PATH=$PATH:/usr/sbin:/sbin
if command -v ss >/dev/null 2>&1 && out=$(ss -H -tuln 2>/dev/null); then
  printf '%s\n' "$out"
  exit 0
fi
echo "@@proc $(uname -m)"
found=0
for p in tcp tcp6 udp udp6; do
  [ -r /proc/net/$p ] || continue
  found=1
  awk -v p=$p 'NR > 1 {print p, $2, $4}' /proc/net/$p
done
[ $found = 1 ]
`

// Queries pending updates from the local package cache only: nothing is
// downloaded or refreshed. Prints manager=, rc=, sec=<severity> <package>
// for security updates (severity "-" when unknown; zypper's package is the
// patch summary, which may contain spaces), upd=<package> for every pending update (apt,
// apk), now= and refreshed=<mtime> for each package index file, whose
// newest one tells when the indexes were last refreshed. nocache=1 marks
// a missing cache where the tool would otherwise just report nothing.
const updatesScript = `PATH=$PATH:/usr/sbin:/sbin
echo "now=$(date +%s)"
stamps() {
  found=0
  for f in "$@"; do
    [ -e "$f" ] && { echo "refreshed=$(stat -c %Y "$f")"; found=1; }
  done
  [ $found = 1 ]
}
if command -v apt-get >/dev/null 2>&1; then
  echo "manager=apt"
  stamps /var/lib/apt/periodic/update-success-stamp /var/lib/apt/lists
  out=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null); echo "rc=$?"
  printf '%s\n' "$out" | awk '/^Inst /{print "upd=" $2; if (tolower($0) ~ /-security/) print "sec=- " $2}'
elif command -v zypper >/dev/null 2>&1; then
  echo "manager=zypper"
  # Without a cache zypper exits 0 and lists nothing.
  stamps /var/cache/zypp/raw/*/repodata/repomd.xml || echo "nocache=1"
  out=$(zypper --non-interactive --no-refresh --quiet list-patches --category security 2>/dev/null); echo "rc=$?"
  # Columns: Repository | Name | Category | Severity | Interactive | Status | Since | Summary
  printf '%s\n' "$out" | awk -F'|' 'NF>=8 {
    for (i=1;i<=NF;i++) gsub(/^ +| +$/, "", $i)
    if ($3=="security" && $6=="needed") { s=$8; sub(/^Security update for (the )?/, "", s); print "sec=" $4 " " s }
  }'
elif command -v dnf >/dev/null 2>&1; then
  case "$(dnf --version 2>/dev/null | head -n 1)" in
    *dnf5*|5.*)
      # dnf5 exits 0 with no output when the cache is missing, so its
      # messages are kept to tell "no updates" from "no data".
      echo "manager=dnf5"
      stamps /var/cache/libdnf5/*/repodata/repomd.xml
      out=$(dnf -q -C advisory list --security 2>&1); echo "rc=$?"
      printf '%s\n' "$out" | awk '/no cache/ {print "nocache=1"} NF>=5 && $2=="security" {print "sec=" $3 " " $4}'
      ;;
    *)
      echo "manager=dnf"
      stamps /var/cache/dnf/*/repodata/repomd.xml
      out=$(dnf -q -C updateinfo list --security 2>/dev/null); echo "rc=$?"
      printf '%s\n' "$out" | awk 'NF>=3 && $1!="Name" {print "sec=" $2 " " $3}'
      ;;
  esac
elif command -v yum >/dev/null 2>&1; then
  echo "manager=yum"
  stamps /var/cache/yum/*/*/*/repomd.xml
  out=$(yum -q -C updateinfo list security 2>/dev/null); echo "rc=$?"
  printf '%s\n' "$out" | awk 'NF>=3 {print "sec=" $2 " " $3}'
elif command -v apk >/dev/null 2>&1; then
  # apk has no security metadata: every pending update is listed. Without
  # a cache it warns, exits 0 and lists nothing.
  echo "manager=apk"
  stamps /var/cache/apk/APKINDEX.*.tar.gz
  out=$(apk list -u 2>&1); echo "rc=$?"
  printf '%s\n' "$out" | awk '/opening from cache/ && /No such file/ {print "nocache=1"} /upgradable from/ {print "upd=" $1}'
fi
true
`

// Compares the running kernel with the newest one installed in /boot, and
// looks for the reboot flag files that Debian/Ubuntu and SUSE create.
const rebootScript = `echo "running=$(uname -r)"
latest=$(ls -1 /boot/vmlinuz-* 2>/dev/null | sed 's|^/boot/vmlinuz-||' | grep -v rescue | sort -V | tail -n 1)
echo "latest=$latest"
for f in /run/reboot-required /run/reboot-needed; do
  [ -f "$f" ] && echo "flag=$f"
done
[ -f /run/reboot-required.pkgs ] && sed 's/^/pkg=/' /run/reboot-required.pkgs
true
`

// Ubuntu only: prints the Ubuntu Pro ESM services whose apt sources are
// set up (the Pro client removes them when a service is disabled), then
// "end". The directory is world-readable, so no privilege is needed.
const esmScript = `d=/etc/apt/sources.list.d
[ -d "$d" ] || exit 1
for s in esm-infra esm-apps; do
  if [ -f "$d/ubuntu-$s.sources" ] || [ -f "$d/ubuntu-$s.list" ]; then echo "$s"; fi
done
echo end
`

// Prints "user<TAB>file<TAB>key line" for every authorized key of every
// account, from the files sshd's AuthorizedKeysFile names (%h, %u, %U and
// %% expanded; relative paths are under the home directory). Needs root to
// read other users' home directories.
const authKeysScript = `PATH=$PATH:/usr/sbin:/sbin
` + sshdOptsFunc + `set -f # split $akf and the sshd options on spaces without globbing
akf=$(sshd -T $(sshd_opts) 2>/dev/null | awk '$1=="authorizedkeysfile" {$1=""; print}')
[ -n "$akf" ] || akf=".ssh/authorized_keys .ssh/authorized_keys2"
while IFS=: read -r name _ uid _ _ home _; do
  for p in $akf; do
    [ "$p" = none ] && continue
    f=$(printf '%s\n' "$p" | sed -e "s|%h|$home|g" -e "s|%u|$name|g" -e "s|%U|$uid|g" -e 's|%%|%|g')
    case "$f" in /*) ;; *) f="$home/$f" ;; esac
    [ -f "$f" ] || continue
    awk -v u="$name" -v f="$f" '!/^[[:space:]]*(#|$)/ {print u "\t" f "\t" $0}' "$f"
  done
done < /etc/passwd
true
`

// Prints "user state expired" for every account in /etc/shadow, where
// state is set (a password hash), empty, or locked (anything else: "!",
// "*", "!!", "!<hash>", or a placeholder like "locked"). Hashes never leave
// the host. expired is 1 when the account expiry date has passed.
const shadowScript = `today=$(( $(date +%s) / 86400 ))
awk -F: -v today="$today" '{
  p = $2
  if (p == "") s = "empty"
  else if (p ~ /^\$[^$]+\$/ || (length(p) == 13 && p ~ /^[.\/0-9A-Za-z]+$/)) s = "set"
  else s = "locked"
  e = ($8 != "" && $8 + 0 > 0 && $8 + 0 <= today) ? 1 : 0
  print $1, s, e
}' /etc/shadow
`

// Asks sudo itself what each login-capable account may run. This follows
// aliases, includes and LDAP rules that a sudoers parser would miss.
const sudoRightsScript = `PATH=$PATH:/usr/sbin:/sbin
command -v sudo >/dev/null 2>&1 || exit 0
awk -F: '$7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | while read -r u; do
  echo "@@user $u"
  LC_ALL=C sudo -n -l -U "$u" 2>/dev/null
done
true
`

// Reports firewall state from ufw, firewalld, nftables and iptables. The
// nft ruleset and iptables INPUT chain are printed raw between markers and
// parsed in Go. Needs root for nft and iptables.
const firewallScript = `PATH=$PATH:/usr/sbin:/sbin
if command -v ufw >/dev/null 2>&1; then echo "ufw=$(ufw status 2>/dev/null | head -n 1)"; fi
if command -v firewall-cmd >/dev/null 2>&1; then echo "firewalld=$(firewall-cmd --state 2>&1 | head -n 1)"; fi
if command -v nft >/dev/null 2>&1; then
  echo "@@nft"
  nft list ruleset 2>/dev/null
  echo "@@end"
fi
if command -v iptables >/dev/null 2>&1; then
  echo "@@iptables"
  iptables -S INPUT 2>/dev/null
  echo "@@end"
fi
true
`

// Lists SUID files and world-writable entries in system directories.
// Package ownership is checked with dpkg or rpm; on merged-/usr systems
// the /bin <-> /usr/bin twin path is tried too. /var is skipped except
// /var/tmp, because container storage under /var/lib holds countless
// copies of SUID binaries.
const filesScript = `owned() {
  f=$1
  case "$f" in
    /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt=${f#/usr} ;;
    /bin/*|/sbin/*|/lib/*|/lib64/*) alt=/usr$f ;;
    *) alt="" ;;
  esac
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -S "$f" >/dev/null 2>&1 && return 0
    [ -n "$alt" ] && dpkg -S "$alt" >/dev/null 2>&1 && return 0
    return 1
  elif command -v rpm >/dev/null 2>&1; then
    rpm -qf "$f" >/dev/null 2>&1 && return 0
    [ -n "$alt" ] && rpm -qf "$alt" >/dev/null 2>&1 && return 0
    return 1
  fi
  return 2
}
dirs=""
for d in /bin /sbin /usr /opt /etc /tmp /var/tmp /home /root /srv; do
  [ -d "$d" ] && [ ! -L "$d" ] && dirs="$dirs $d"
done
find $dirs -xdev -type f -perm -4000 2>/dev/null | head -n 500 | while read -r f; do
  owned "$f"; case $? in 0) o=pkg ;; 1) o=none ;; *) o=unknown ;; esac
  echo "suid=$o $f"
done
find /etc /bin /sbin /usr /opt -xdev \( -type f -perm -0002 \) -o \( -type d -perm -0002 ! -perm -1000 \) 2>/dev/null | head -n 200 | while read -r f; do
  if [ -d "$f" ]; then echo "ww=d $f"; else echo "ww=f $f"; fi
done
true
`
