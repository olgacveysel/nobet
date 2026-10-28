package collect

import (
	"sort"
	"strconv"
	"strings"
)

// Credential is a file holding credentials (a password, token or cloud
// secret) that every account can read. Only its path and what it is leave
// the host: the collector checks the content there.
type Credential struct {
	Path  string `json:"path"`
	What  string `json:"what"`  // for example "AWS credentials"
	Owner string `json:"owner"` // the account that owns the file
}

// credentialsScript looks for well-known credential files in every
// account's home, the .env files of applications under /opt, /srv and
// /var/www, WordPress configs, and a few system files, and keeps those
// whose content shows they hold a secret (a .my.cnf with only a user name
// does not). It prints each one's path and label, then the owner and mode
// of it and every directory above it.
const credentialsScript = `# check FILE LABEL PATTERN: print the file when it exists and its content
# matches PATTERN (extended, case-insensitive). Nothing of the content is
# printed.
check() {
  [ -f "$1" ] && [ ! -L "$1" ] && grep -qiE -- "$3" "$1" 2>/dev/null && echo "cred|$2|$1"
}
cands() {
  awk -F: '$6 ~ /^\/./ { print $6 }' /etc/passwd | sort -u | while IFS= read -r h; do
    check "$h/.pgpass" "PostgreSQL password file" '^[^#[:space:]]'
    check "$h/.my.cnf" "MySQL client config with a password" '^[[:space:]]*password[[:space:]]*='
    check "$h/.netrc" "netrc with a password" 'password'
    check "$h/.git-credentials" "Git credentials" '://[^:/@]+:[^@]+@'
    check "$h/.aws/credentials" "AWS credentials" 'aws_secret_access_key'
    check "$h/.docker/config.json" "Docker registry credentials" '"auth"[[:space:]]*:[[:space:]]*"[^"]'
    check "$h/.kube/config" "Kubernetes credentials" '(token|client-key-data|password):'
    check "$h/.config/gh/hosts.yml" "GitHub CLI token" 'oauth_token'
    check "$h/.npmrc" "npm token" '_auth'
    check "$h/.pypirc" "PyPI password" 'password'
    check "$h/.vault-token" "Vault token" '.'
    check "$h/.s3cfg" "S3 credentials" 'secret_key[[:space:]]*='
    check "$h/.config/rclone/rclone.conf" "rclone remote credentials" '^(pass|token|secret_access_key)[[:space:]]*='
    check "$h/.config/gcloud/application_default_credentials.json" "Google Cloud credentials" '(private_key|refresh_token)'
  done
  for f in /opt/*/.env /opt/*/*/.env /srv/*/.env /srv/*/*/.env /var/www/*/.env /var/www/*/*/.env; do
    check "$f" "application secrets (.env)" '^[[:space:]]*(export[[:space:]]+)?[A-Za-z0-9_]*(pass|secret|token|key|credential)[A-Za-z0-9_]*[[:space:]]*=[[:space:]]*[^[:space:]#]'
  done
  for f in /var/www/*/wp-config.php /var/www/*/*/wp-config.php; do
    check "$f" "WordPress database password" 'DB_PASSWORD'
  done
  # Password hashes: a field that is not empty, x, or only locked (! or *).
  # /etc/passwd is world-readable by design, so only hashes in it count.
  for f in /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- /var/backups/shadow.bak /var/backups/gshadow.bak /etc/security/opasswd /etc/passwd /etc/passwd-; do
    check "$f" "password hashes" '^[^:]*:[!*]*([^:!*x]|x[^:])'
  done
  check /etc/mysql/debian.cnf "MySQL maintenance account" '^[[:space:]]*password[[:space:]]*='
  check /etc/postfix/sasl_passwd "mail relay password" '^[^#[:space:]]'
  check /etc/msmtprc "mail relay password" '^[[:space:]]*password'
  check /etc/ssmtp/ssmtp.conf "mail relay password" '^[[:space:]]*AuthPass'
}
# Credential lines go to stdout (4); each file's path and the directories
# above it go through 3 to stat.
{ cands | LC_ALL=C sort -u | head -n 2000 | while IFS='|' read -r tag what f; do
  echo "$tag|$what|$f"
  q=$f
  while [ -n "$q" ]; do echo "$q" >&3; q=${q%/*}; done
done 3>&1 1>&4 | { echo /; sort -u; } | tr '\n' '\0' | xargs -0 stat -c 'stat|%u|%g|%a|%F|%n' 2>/dev/null; } 4>&1
echo "@@end"
`

// parseCredentials reads credentialsScript output and keeps the files
// every account can read: readable by others, below directories others can
// enter. Group-readable files are left out: a web server's group reading
// its site's config is by design. It returns nil when the output is
// incomplete.
func (f *Facts) parseCredentials(s string) []Credential {
	entries, _, _, _ := parsePaths(s)
	if entries == nil {
		return nil
	}
	names := map[int]string{}
	for _, e := range f.Passwd {
		if _, dup := names[e.UID]; !dup {
			names[e.UID] = e.Name
		}
	}
	out := []Credential{}
	for _, line := range strings.Split(s, "\n") {
		p := strings.SplitN(strings.TrimRight(line, "\r"), "|", 3)
		if len(p) != 3 || p[0] != "cred" {
			continue
		}
		what, path := p[1], p[2]
		if !everyoneCanRead(path, entries) {
			continue
		}
		owner, ok := names[entries[path].UID]
		if !ok {
			owner = "uid " + strconv.Itoa(entries[path].UID)
		}
		out = append(out, Credential{Path: path, What: what, Owner: owner})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// everyoneCanRead reports whether every account can read the file at p:
// readable by others, and every directory above it enterable by others.
func everyoneCanRead(p string, entries map[string]PathEntry) bool {
	st, ok := entries[p]
	if !ok || st.Type != "file" || st.Mode&0o004 == 0 {
		return false
	}
	for _, d := range chain(p)[1:] {
		de, ok := entries[d]
		if !ok || de.Type != "dir" || de.Mode&0o001 == 0 {
			return false
		}
	}
	return true
}
