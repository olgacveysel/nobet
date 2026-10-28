package collect

import (
	"strings"
)

// DockerAPI is how root's dockerd serves its API over TCP.
type DockerAPI struct {
	Hosts  []string `json:"hosts"`            // tcp:// addresses, from -H/--host and daemon.json "hosts"
	TLS    bool     `json:"tls"`              // the TCP API speaks TLS
	Verify bool     `json:"verify,omitempty"` // and requires client certificates signed by its CA
}

// Open reports whether anyone who reaches the API can use it: no TLS, or
// TLS without client certificates.
func (d DockerAPI) Open() bool { return len(d.Hosts) > 0 && !(d.TLS && d.Verify) }

// dockerAPIScript prints, for every dockerd running as root, its command
// line (which ps shows every account anyway), DOCKER_TLS_VERIFY from its
// environment (nothing else of it) and, from its daemon.json, the tcp://
// entries of "hosts" and the "tls" and "tlsverify" settings only. A
// rootless dockerd runs as its account and is left out.
const dockerAPIScript = `for p in /proc/[0-9]*; do
  { read -r comm < $p/comm; } 2>/dev/null || continue
  [ "$comm" = dockerd ] && [ "$(stat -c %u $p 2>/dev/null)" = 0 ] || continue
  echo "@@dockerd ${p#/proc/}"
  args=$(tr '\0' '\n' 2>/dev/null < $p/cmdline)
  printf '%s\n' "$args" | sed 's/^/arg|/'
  tr '\0' '\n' 2>/dev/null < $p/environ | grep '^DOCKER_TLS_VERIFY=' | sed 's/^/env|/'
  cfg=/etc/docker/daemon.json prev=
  while IFS= read -r a; do
    [ "$prev" = --config-file ] && cfg=$a
    case $a in --config-file=*) cfg=${a#--config-file=} ;; esac
    prev=$a
  done <<EOF
$args
EOF
  if [ -r "$cfg" ]; then
    j=$(tr -d '\r\n' < "$cfg")
    printf '%s' "$j" | grep -oE '"hosts"[[:space:]]*:[[:space:]]*\[[^]]*\]' | grep -oE 'tcp://[^"]*' | sed 's/^/json|host|/'
    printf '%s' "$j" | grep -oE '"(tls|tlsverify)"[[:space:]]*:[[:space:]]*(true|false)' | tr -d ' "\t' | sed 's/:/|/; s/^/json|/'
  elif [ -e "$cfg" ]; then
    echo "error|cannot read $cfg"
  fi
done
echo "@@end"
`

// parseDockerAPI reads dockerAPIScript output: nil and the reason when it
// is incomplete, an empty list without a root dockerd.
//
// dockerd 29.9 (checked 2026-10-28): TCP without TLS serves the whole API
// to anyone (it only delays startup by 15 s with a warning). With TLS, client
// certificates are required unless tlsverify is explicitly false, and
// setting tlsverify at all (even false) turns TLS on. --tls without a CA
// file fails to start. DOCKER_TLS_VERIFY in dockerd's environment makes
// verifying the default.
func parseDockerAPI(s string) ([]DockerAPI, string) {
	out := []DockerAPI{}
	type flags struct {
		hosts       []string
		tls, verify *bool
		envVerify   bool
	}
	var cur *flags
	finish := func() {
		if cur == nil {
			return
		}
		d := DockerAPI{Hosts: cur.hosts}
		verify := cur.verify
		if verify == nil && cur.envVerify {
			t := true
			verify = &t
		}
		d.TLS = (cur.tls != nil && *cur.tls) || verify != nil
		d.Verify = d.TLS && (verify == nil || *verify)
		if len(d.Hosts) > 0 {
			out = append(out, d)
		}
		cur = nil
	}
	b := func(v string) *bool { t := v != "false"; return &t }
	var args []string
	flush := func() { // command-line flags, the way dockerd's flag parser reads them
		for i := 1; i < len(args); i++ {
			a := args[i]
			name, val, hasVal := strings.Cut(a, "=")
			switch {
			case name == "-H" || name == "--host":
				if !hasVal && i+1 < len(args) {
					i++
					val = args[i]
				}
				if strings.HasPrefix(val, "tcp://") {
					cur.hosts = append(cur.hosts, val)
				}
			case strings.HasPrefix(a, "-H") && !strings.HasPrefix(a, "--"):
				if v := strings.TrimPrefix(a, "-H"); strings.HasPrefix(v, "tcp://") {
					cur.hosts = append(cur.hosts, v)
				}
			case name == "--tls":
				cur.tls = b(val)
			case name == "--tlsverify":
				cur.verify = b(val)
			}
		}
		args = nil
	}
	for _, line := range lines(s) {
		kind, rest, _ := strings.Cut(line, "|")
		switch {
		case line == "@@end":
			if cur != nil {
				flush()
			}
			finish()
			return out, ""
		case strings.HasPrefix(line, "@@dockerd "):
			if cur != nil {
				flush()
			}
			finish()
			cur = &flags{}
		case cur == nil:
		case kind == "arg":
			args = append(args, rest)
		case kind == "env":
			cur.envVerify = strings.TrimPrefix(rest, "DOCKER_TLS_VERIFY=") != ""
		case kind == "error":
			return nil, "dockerd: " + rest
		case kind == "json":
			k, v, _ := strings.Cut(rest, "|")
			switch k {
			case "host":
				cur.hosts = append(cur.hosts, v)
			case "tls":
				cur.tls = b(v)
			case "tlsverify":
				cur.verify = b(v)
			}
		}
	}
	return nil, "the dockerd listing stopped early"
}
