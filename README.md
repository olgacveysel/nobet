<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/nobet-owl-wordmark.svg">
    <img alt="nöbet" src="docs/logo/nobet-owl-wordmark-light.svg" width="380">
  </picture>
</p>

# Nöbet (`nobet`)

**Your servers' night watch.** Nöbet audits the security of Linux servers, either the machine it runs on or remote hosts over SSH: SSH configuration, root and sudo access, exposed services and more. It is built for small teams (up to roughly 50 servers) that want answers without deploying agents or a SIEM.

*Nöbet* is Turkish for a watch or guard shift.

> Status: early development (v0.3).

## Principles

- **Two modes, one binary.** Scan the local machine directly, or many remote hosts in parallel over SSH. Every check works the same in both.
- **Agentless.** For remote scans nothing is installed on your servers. Nöbet connects with your existing SSH keys and agent.
- **Read-only.** Every remote command only reads state.
- **Strict host keys.** Hosts must already be in `known_hosts`. Nöbet never trusts an unknown or changed host key.
- **Honest about gaps.** If a check can't run (for example, it needs root), the report says it was skipped instead of passing it silently.

## Install

Download a binary from the [releases page](https://github.com/olgacveysel/nobet/releases) (Linux, macOS and Windows; amd64 and arm64), or install the `nobet` `.deb`, `.rpm` or `.apk` package. The optional team dashboard is a separate `nobet-web` package (see [Team dashboard](#team-dashboard-nobet-web)).

With Go 1.26 or newer:

```bash
go install github.com/olgacveysel/nobet/cmd/nobet@latest
```

To build from a checkout: `make test build` (builds `nobet` and `nobet-web`).

### Verify a download

Releases come with an SPDX SBOM per archive (`*.sbom.json`) and a signed `checksums.txt`. The signature is keyless ([Sigstore](https://www.sigstore.dev/)): it proves the file was made by this repository's release workflow (run for a tag, or started by hand from `master` to rebuild a tag's release), and it is recorded in a public transparency log. With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/olgacveysel/nobet/\.github/workflows/release\.yml@refs/(tags/v|heads/master$)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Usage

```bash
# Scan this machine (sudo gives full results)
sudo nobet scan

# Scan remote hosts over SSH, in parallel
nobet scan web01 admin@db01:2222

# Scan an inventory file (see hosts.example), plus this machine
nobet scan -local -i hosts.txt

# Scan the web and db groups of an Ansible inventory
nobet scan -i inventory.ini -group web,db

# JSON for scripts and CI; exit code 1 if anything is medium or worse
nobet scan -json -fail-on medium -i hosts.txt > report.json
```

In an interactive terminal, results open in the TUI: hosts appear as they finish, and you can browse each host's findings (↑/↓ select host, PgUp/PgDn scroll, `f` filter by severity, `r` root access map, `q` quit). When output is piped or redirected, or with `-plain` or `-json`, nobet prints plain output instead, so scripts and cron jobs are unaffected.

Run `nobet help scan` for all flags. Flags must come before host arguments. `nobet checks` lists every check ID, for writing allowlist rules.

Hosts are resolved through `~/.ssh/config` and `/etc/ssh/ssh_config` like `ssh` does: aliases (`HostName`), `User`, `Port`, `IdentityFile` and `ProxyJump` (including chains such as `ProxyJump gw1,bastion`). Values you give explicitly (`user@host:port`, `-u`) win over the config. Use `-F <file>` (`-ssh-config`) to read one config file instead, like `ssh -F`, or `-no-ssh-config` to ignore it. `ProxyCommand` is not supported; hosts that need it are reported with a clear error.

`-i` also reads Ansible inventories: INI files directly (groups, `:children`, `:vars`, host ranges like `web[01:10]`, and `ansible_host`, `ansible_port` and `ansible_user`, with Ansible's precedence), and YAML or dynamic inventories through the JSON that `ansible-inventory -i inventory.yml --list > inventory.json` prints. Hosts keep their inventory names in reports, `-group` picks groups (children included), and hosts with `ansible_connection=local` are skipped (use `-local`).

Keys come from ssh-agent (`SSH_AUTH_SOCK`; on Windows the OpenSSH Authentication Agent service is used automatically), the config's `IdentityFile`s, and unencrypted keys in `~/.ssh` or given with `-identity`.

Short forms: `nobet s` for `scan`, `nobet r` for `rootmap`, `nobet d` for `diff`, `nobet c` for `checks`, `nobet -v` for `version` and `nobet -h` for `help`. Common flags also have one-letter forms: `-j` (`-json`), `-p` (`-plain`), `-l` (`-local`), `-f` (`-fail-on`) `-t` (`-timeout`) and `-F` (`-ssh-config`).

### Root access map

```bash
nobet rootmap -i hosts.txt
```

`rootmap` answers "who can become root on which host, and how?" across your whole fleet. It combines every account's authorized SSH keys with its routes to root: direct UID 0 login (respecting `PermitRootLogin`), `sudo ALL` as resolved by sudo itself (`sudo -l -U`, so aliases, includes and LDAP rules count), limited sudo rules that escape to a shell (`sudo vim`, `sudo less`, `sudo find`, see [GTFOBins](https://gtfobins.github.io)), root-equivalent groups, and files root runs that the account can change (a cron job's script in a directory it owns, a service binary it can write, the program a sudo rule names; see FS-003). Keys are read from the files sshd's `AuthorizedKeysFile` names, and a key only counts when sshd lets its account log in with it (`PubkeyAuthentication`, `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`). `Match` blocks count too: a route or key that sshd allows only from some networks says so (`UID 0 login from 10.0.0.0/8`). Password states from `/etc/shadow` and sudo's own Defaults refine the routes: a sudo rule that asks for a locked password, or for root's password (`rootpw`, `targetpw`, as on openSUSE), is no route at all, and one that asks for an empty password (or none, `!authenticate`) is free. Keys that come from `AuthorizedKeysCommand` or user certificates (`TrustedUserCAKeys`) cannot be listed; they are reported under INCOMPLETE. Results are grouped by SSH key, so a single key that opens root on many hosts stands out:

```
ROOT ACCESS BY SSH KEY

SHA256:tnsW9C5r…  ed25519  veysel@laptop
  root on 3 host(s):
    web01  as deploy  via sudo ALL, no password  (last login 2026-10-20)
    web02  as root    via UID 0 login  (no login since 2026-06-01)
    db01   as ops     via docker group  [only from "10.0.0.5"]  (last login 2026-10-21)

ROOT-CAPABLE ACCOUNTS WITHOUT SSH KEY ACCESS
    web02  backup  via sudo ALL, password required

INCOMPLETE
    db02   not scanned: connection refused
```

A line starting with `!` means the key's private half can be read by more than its owner (FS-004): `! private key readable by every account on web03: /home/alice/.ssh/id_ed25519`. The last login comes from sshd's log messages (see ACC-006); "no login since" gives the date the logs begin. Use `-json` for machine-readable output. Full results need root or passwordless sudo on every host.

#### Key owners and offboarding

A key comment like `veysel@laptop` is whatever someone typed. To have the map name people reliably, list who owns which key in `~/.config/nobet/keys` (or pass `-keys FILE`; see [keys.example](keys.example)):

```
alice  SHA256:52JZmNfuKifllhTBswzRjmhmtxlcsa2aXf71Sl853cQ   # laptop
alice  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@desktop
ci     SHA256:HRmMEMU9cyejr7STBxyzzOI4cfmC7Xkho7aTuOfNdNA   # deploy pipeline
```

Each key is then labelled with its owner, and keys that lead to root without an owner in the file are counted and marked `(no known owner)`. The same file names owners in the TUI's root view, the HTML and PDF reports and `nobet-web -keys`. When someone leaves:

```bash
nobet rootmap -i hosts.txt -who alice
```

lists every host where Alice's keys reach root, any other key that reaches an account named `alice`, and `alice` accounts that can become root without a key. Without a keys file, `-who` matches key comments (`alice` or `alice@...`) instead.

### HTML and PDF reports

```bash
nobet scan -p -i hosts.txt -html report.html -pdf report.pdf
```

`-html` writes a single self-contained HTML file (no external scripts, fonts or images) and `-pdf` an A4 PDF, both with a severity summary, a table of hosts (worst first), every host's findings with fixes and since when each has been open (from the scan history), allowlisted findings with their reasons, skipped checks, and the root access map. The files are created with mode 0600 because they describe weaknesses and access paths. The dashboard offers the same reports for download, from each host's newest scan.

`nobet report` writes them from the saved history without scanning, from each host's newest successful scan, for example for a weekly report from cron (`-host 'web*'` narrows it to some hosts):

```bash
nobet report -history-dir /var/lib/nobet/scans -pdf weekly.pdf
```

In the TUI, press `r` to switch to the root access map for the hosts scanned so far.

### Allowlist

Some findings are expected: your scanning account needs passwordless sudo, web servers listen on 443. Put reviewed exceptions in `~/.config/nobet/allowlist` (or pass `-allow <file>`), one rule per line:

```
# <check-id>  <host-glob>  [text to match]   # reason
ACC-002  *     nobet-scan   # scanning account needs passwordless sudo
NET-001  web*  tcp/443      # public web servers
*        lab-*              # lab machines are out of scope
CTR-001  *     traefik  until=2027-01-31  # needs the Docker socket; review
```

A rule with `until=YYYY-MM-DD` covers findings through that day and none after it, so an accepted risk comes back for review instead of staying hidden for good; scans say on stderr which rules have ended and which end within two weeks, and the dashboard and reports show the date with each allowlisted finding.

Allowlisted findings disappear from reports and no longer affect the exit code, but they are counted ("3 allowlisted") and listed with their reason in `-json` output, so nothing is hidden silently. See `allowlist.example`.

### Alerts on changes

```bash
nobet scan -i hosts.txt -on-change /etc/nobet/on-change
```

When a scan finds changes since the previous one, nöbet runs the `-on-change` command (through `sh -c`) with the changes as JSON on stdin, in the format of `nobet diff -json` but only for the hosts that changed. It also sets `NOBET_CHANGES` and `NOBET_CHANGED_HOSTS` to the counts, and `NOBET_SUMMARY` to a few lines for a chat message or mail (also as a JSON string in `NOBET_SUMMARY_JSON`). The command's output goes to stderr; if it fails or takes longer than two minutes, the scan reports that and carries on. [`contrib/hooks/slack`](contrib/hooks/slack) posts the summary to a Slack or Mattermost webhook with curl or busybox wget. nöbet itself never makes HTTP requests.

### What changed: `nobet diff`

Every scan is saved to `~/.local/share/nobet/scans` (directory mode 0700, files 0600; the newest 100 are kept; skip with `-no-save`). Use `-history-dir DIR` on `scan` and `diff`, or set `NOBET_DATA_DIR` (history in `$NOBET_DATA_DIR/scans`), to keep a shared history instead; in a directory you made group-readable, scans are saved 0640. After a scan, nöbet tells you how many things changed since that host's previous scan, and `nobet diff` shows them:

```
== web01  (2026-10-11 09:00 → 2026-10-12 09:00)
  +  root     deploy via sudo ALL, no password
  +  key      deploy: SHA256:Xb3…  unknown@laptop
  ~  sshd     passwordauthentication: no → yes
  +  port     tcp [::]:6379
  -  finding  UPD-001 3 pending security update(s)
```

Changes to root access and keys are only compared when both scans were privileged, so a scan without sudo never produces false alarms. `nobet diff` exits with status 1 when anything changed, which makes a simple cron alert possible: `nobet scan -p -i hosts.txt >/dev/null; nobet diff -host 'db*' || mail ...`.

`nobet diff -since 7d` (or `2w`, `36h`) compares each host's newest scan with its newest scan from before then, instead of with the previous scan: everything that changed this week, for a weekly review. Hosts with no scan that old are named, not compared.

For complete remote results, the SSH user should be root or have passwordless sudo, because reading the effective sshd config and sudoers requires root. Without it, those checks are reported as skipped.

## Team dashboard: `nobet-web`

`nobet-web` is a separate, optional binary and package that shows the scan history to your team in a browser: fleet status with a 30-day trend, findings by check (which hosts have each problem, where it is allowlisted and why), each host's findings (with how long each has been open, and which are new in the newest scan) and scan history, every change between scans, and the root access map.

**It is read-only by design.** It never scans, never connects to your servers and holds no SSH keys (its build is tested to contain no SSH client at all). A systemd timer runs `nobet scan` under a service account and saves to a shared history directory, which the dashboard only reads. If the dashboard were compromised, an attacker would learn your weaknesses but could not act on them; with scan requests turned on, they could at most ask for more read-only scans of hosts the scanner already knows.

**Access control comes first.** By default it listens on `127.0.0.1:8080` and belongs behind a reverse proxy that authenticates your team (oauth2-proxy, Authelia, Authentik, Pomerium or your SSO). If the proxy passes the signed-in user in a header, add `-user-header X-Forwarded-User` (or `Remote-User`, ...) to log who viewed which page. `-keys /etc/nobet/keys` names key owners on the root access page (the file is read on every view). The root access map shows which key opens which server, so never expose the dashboard directly.

Setup on the machine that scans (the units are in `contrib/systemd`; the packages also install them under `/usr/share/doc/nobet*/examples`):

```bash
# 1. A scanning account that owns the SSH key, and a separate dashboard account
#    that may read the scans but not the key.
sudo useradd --system --home-dir /var/lib/nobet --create-home --shell /usr/sbin/nologin nobet
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nobet-web
sudo usermod -aG nobet nobet-web
sudo chmod 0750 /var/lib/nobet
sudo install -d -o nobet -g nobet -m 2750 /var/lib/nobet/scans

# 2. The scanning key. Add its public half on every host (ideally with
#    from="<scanner address>") with passwordless sudo, then connect once per
#    host to verify and record its host key.
sudo -u nobet install -d -m 0700 /var/lib/nobet/.ssh
sudo -u nobet ssh-keygen -t ed25519 -N '' -C nobet-scan -f /var/lib/nobet/.ssh/id_ed25519
sudo -u nobet ssh web01 true

# 3. What to scan. The allowlist may stay empty; "ACC-002 * nobet" accepts
#    the scanning account's own passwordless sudo.
sudo install -d /etc/nobet
sudo cp hosts.txt /etc/nobet/hosts
sudo touch /etc/nobet/allowlist

# 4. A nightly scan and the dashboard.
sudo cp contrib/systemd/nobet-scan.service contrib/systemd/nobet-scan.timer contrib/systemd/nobet-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now nobet-scan.timer nobet-web.service
sudo systemctl start nobet-scan.service   # the first scan now rather than tonight
```

Both units are hardened (`systemd-analyze security` rates the dashboard 1.3 and the scanner 3.4, where 10 is unconfined); the dashboard cannot read `/var/lib/nobet/.ssh` and only accepts local connections. Hosts without a successful scan for 48 hours are flagged (`-stale`).

#### Scans from the dashboard

```bash
install -d -o nobet -g nobet -m 2770 /var/lib/nobet/queue
nobet-web -listen 127.0.0.1:8080 -scan-queue /var/lib/nobet/queue
systemctl enable --now nobet-scan-queue.path
```

With `-scan-queue`, the fleet page offers "Scan all hosts now" and each host page "Rescan this host". nobet-web still never scans and never touches the SSH key: it writes a small request file (who asked, which hosts) to the queue directory, and `nobet scan -queue` (from `nobet-scan-queue.path`, as the `nobet` account) scans the requested hosts that are in its own inventory and records the outcome, which the dashboard shows. One request can wait at a time; requests are in the audit log; the form only works from the dashboard's own pages (Go's cross-origin protection checks `Sec-Fetch-Site` and `Origin`). Everyone who may view may ask for scans unless `-scan-users` (or, with sign-in, `-scan-groups`) narrows it. In Docker, add `"-scan-queue", "/var/lib/nobet-queue"` to the web service's command; the scanner checks that queue every 30 seconds.

#### Sign-in

Instead of a reverse proxy, nobet-web can sign people in with your OpenID Connect provider (Keycloak, Authentik, Entra ID, Google, Okta, Dex, ...). Everyone who signs in gets the same read-only view; who may sign in is your choice, and nobody may by default:

```bash
head -c 32 /dev/urandom > /etc/nobet/session-key      # keeps sessions across restarts
nobet-web -listen 127.0.0.1:8080 -public-url https://nobet.example.com \
  -oidc-issuer https://login.example.com/realms/ops -oidc-client-id nobet \
  -oidc-client-secret-file /etc/nobet/oidc-secret \
  -allow-groups nobet-viewers -session-key-file /etc/nobet/session-key \
  -audit-log /var/log/nobet-web/audit.jsonl
```

Register `https://nobet.example.com/auth/callback` as the client's redirect URI. Allow people by email, username or subject (`-allow-users`), or by group (`-allow-groups`, read from the `groups` claim; `-groups-claim realm_access.roles` for Keycloak roles, and add `groups` to `-oidc-scopes` where the provider needs it). nobet-web uses the authorization code flow with PKCE, checks the state and nonce, and keeps the session in a signed, HttpOnly, SameSite cookie (`__Host-` prefixed over HTTPS) for 8 hours (`-session-ttl`). Serve HTTPS with `-tls-cert`/`-tls-key`, or put a TLS proxy in front. With sign-in, Prometheus cannot scrape the main listener, so use `-metrics-listen 127.0.0.1:9187`.

`-audit-log` appends one JSON line per page view, sign-in, refusal and sign-out, with the user, the page and the time; it works behind a proxy too (with `-user-header`).

```json
{"time":"2026-10-20T21:58:12Z","event":"view","user":"alice@example.com","method":"GET","path":"/root","status":200,"remote":"127.0.0.1:47640"}
```

#### Prometheus metrics

`nobet-web -metrics` also serves `/metrics` for a Prometheus on the same machine (or one your proxy lets through): per host, the findings in its newest successful scan by severity (`nobet_host_findings`), allowlisted findings, findings new in the newest scan (`nobet_host_new_findings`), when the oldest open finding of each severity was first reported (`nobet_host_oldest_finding_opened_timestamp_seconds`), whether the newest attempt succeeded (`nobet_host_up`), whether it is stale (`nobet_host_stale`), the scan times and whether the scan was privileged; for the fleet, the number of SSH keys that lead to root (`nobet_root_keys`, and `nobet_root_keys_unclaimed` with `-keys`). For example:

```yaml
groups:
  - name: nobet
    rules:
      - alert: NobetCriticalFinding
        expr: nobet_host_findings{severity="critical"} > 0
      - alert: NobetHighFindingOpenAWeek
        expr: time() - nobet_host_oldest_finding_opened_timestamp_seconds{severity="high"} > 7 * 86400
      - alert: NobetHostNotScanned
        expr: nobet_host_stale == 1
      - alert: NobetUnclaimedRootKey
        expr: nobet_root_keys_unclaimed > 0
```

### Docker

`compose.yaml` runs the same setup in two containers: `scanner` runs `nobet scan` every 24 hours (`NOBET_INTERVAL`) and is the only one that gets the SSH key; `web` is the dashboard on a distroless image without a shell, with the scan history mounted read-only and the port published on `127.0.0.1` only. Both run as uid 65532 with a read-only root filesystem and no capabilities.

```bash
mkdir -p config secrets
cp hosts.example config/hosts                 # your hosts, one [user@]host[:port] per line
ssh-keygen -F web01 >> config/known_hosts     # each host's key, from a known_hosts you trust
ssh-keygen -t ed25519 -N '' -C nobet-scan -f secrets/id_ed25519
sudo chown 65532 secrets/id_ed25519           # readable by the containers' user only
docker compose up -d
```

Optional files in `config/`: `allowlist`, `ssh_config` for aliases and `ProxyJump`, and an executable `on-change` hook (see [Alerts on changes](#alerts-on-changes); `contrib/hooks/slack` works in the scanner image). The scanner logs each scan (`docker compose logs scanner`); `NOBET_INTERVAL=once` scans once and exits. `config/` and `secrets/` are git-ignored.

Compose runs the release images `ghcr.io/olgacveysel/nobet-scanner` and `ghcr.io/olgacveysel/nobet-web` (amd64 and arm64). Pin a version with `NOBET_VERSION=0.3.0` in a `.env` file next to `compose.yaml` (the default is `latest`, which only moves on releases, not pre-releases); `docker compose up -d --build` builds both from the checkout instead. The images are signed the same way as the downloads, and carry an SBOM and build provenance:

```bash
cosign verify ghcr.io/olgacveysel/nobet-web:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/olgacveysel/nobet/\.github/workflows/release\.yml@refs/(tags/v|heads/master$)' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/olgacveysel/nobet-web:0.3.0 --format '{{ json .SBOM }}'
```

### Scale

Measured with 50 hosts (the size nöbet is built for): a full scan takes about 10 seconds at the default concurrency (`-c 10`) and under 30 MB of memory. With the maximum history of 100 such scans (about 80 MB on disk), `nobet diff` takes 0.4 seconds and the dashboard uses about 27 MB; both read the history one scan at a time.

## Checks

| ID      | Severity        | What it finds |
|---------|-----------------|---------------|
| SSH-001 | High / Low      | Root can log in over SSH (with any method / key only) |
| SSH-002 | Medium / Low    | Password or PAM keyboard-interactive authentication enabled |
| SSH-003 | Critical        | Empty passwords accepted |
| SSH-004 | Low             | X11 forwarding enabled |
| SSH-005 | Medium / Low    | Weak or deprecated algorithms offered: Medium for RC4, 3DES, Blowfish, MD5 MACs, 1024-bit DH and DSA keys; Low for CBC ciphers and SHA-1 key exchange or signatures (`ssh-rsa`) |
| ACC-001 | Critical        | Accounts other than root with UID 0 |
| ACC-002 | High / Medium   | Passwordless sudo rules, or sudo authentication disabled |
| ACC-003 | High            | Members of root-equivalent groups (docker, lxd, incus) |
| ACC-004 | High            | Limited sudo rules that still give a root shell or root file writes (editors, pagers, interpreters, `find`, `tee`… see GTFOBins) |
| ACC-005 | Critical / High | Accounts with an empty password that can log in; Critical when the account can become root |
| ACC-007 | Medium / Low    | Passwords stored as DES or MD5 hashes, which a leaked `/etc/shadow` gives away quickly; Medium when the account can become root. Only the algorithm's name is read |
| ACC-006 | Medium / Low    | Authorized SSH keys that have not logged in for 90 days, from sshd's log messages (see below); Medium when the key reaches an account that can become root |
| LOG-001 | Medium / Low    | Login records not kept for 90 days: Medium when sshd logs no logins (`LogLevel`), nothing keeps its messages, or they only live in a journal in memory; Low when they go back less than 90 days on a system that is older than that |
| NET-001 | Critical / High / Info | The Docker API open to clients without a certificate, from dockerd's own settings: TCP without TLS on any port, or TLS with `tlsverify=false` (Critical: root for anyone who can connect; High when bound to loopback, which is every local account); without root, a listener on port 2375. Databases and admin APIs listening on all interfaces, or published there by a container (named in the finding; also with Docker's `userland-proxy` off, when no socket listens) |
| NET-002 | Medium / Low    | No host firewall filtering incoming traffic (ufw, firewalld, nftables, iptables); Medium when services are exposed. Low when a firewall is active but Docker publishes ports past it (see below) |
| NET-003 | Critical / High / Medium | NFS exports that give away root or every account's files: root on a client is root in a writable export (`no_root_squash`, or `anonuid=0`): Critical when every host may mount it (`*`), High for named hosts. On exports every host may mount, also High for reading as root or writing as any account, Medium for reading as any account. Kerberos-only exports (`sec=krb5*`) are not reported |
| CTR-001 | High / Medium / Low | Running Docker, podman, Incus or LXD containers that can take over the host: privileged (Incus/LXD `security.privileged`), a control socket mounted (Docker, podman, containerd, Incus, LXD, systemd, D-Bus), host paths root runs writable (`/etc/cron.d`, `/usr`, `/`…), escape capabilities (`SYS_ADMIN`, `SYS_MODULE`…), raw disks; Medium for the host's PID namespace or read access to `/etc/shadow`, SSH keys; Low without seccomp or AppArmor |
| FS-001  | Critical / High / Medium | SUID on programs that spawn a root shell (bash, find, vim, python…), SUID files in /tmp or home directories, SUID files not owned by any package |
| FS-002  | High            | World-writable files, or world-writable directories without the sticky bit, in /etc, /usr, /bin, /sbin, /opt |
| FS-003  | Critical / High | Files root runs or trusts that other accounts can change: Critical when anyone can, High when named accounts can (see below) |
| FS-004  | Critical / High / Medium | Private keys other accounts can read: accounts' SSH keys, sshd's host keys, TLS keys. High when every account can, Medium for a group or accounts an ACL names; one step higher when the key logs in to a root-capable account on the host |
| FS-005  | High            | Credential files every account can read: `.pgpass`, `.my.cnf`, `.netrc`, `.git-credentials`, `~/.aws/credentials`, Docker registry auth, `~/.kube/config`, GitHub CLI, npm, PyPI, Vault, S3, rclone and Google Cloud credentials, application `.env` files and WordPress configs, and password hashes (`/etc/shadow`, `/etc/gshadow`, their backups, `/etc/security/opasswd`, hashes left in `/etc/passwd`). Only files whose content holds a secret count; nothing of it leaves the host |
| KRN-001 | Medium / Low    | Kernel hardening switched off: ASLR (`kernel.randomize_va_space`), symlink and hardlink protection, readable setuid core dumps (`fs.suid_dumpable = 1`), SYN cookies, source routing. Only settings whose defaults are safe on every supported distribution are checked |
| UPD-001 | High / Medium   | Pending security updates (apt, dnf, dnf5, yum, zypper); High when the vendor rates any as critical or important. apk (Alpine) does not label security fixes, so there every pending update is reported, as Medium |
| UPD-002 | Medium          | Reboot required: newer kernel installed than running, or a reboot flag file exists |
| UPD-003 | Low             | Package indexes not refreshed for more than 7 days, so update counts may be incomplete (all supported package managers) |
| UPD-004 | High / Low / Info | The OS release is past its end of support (High) or reaches it within 180 days (Low). Ubuntu hosts with Ubuntu Pro ESM (esm-infra) enabled are Info until ESM ends; for paid extended support elsewhere (RHEL ELS, SLES LTSS, Debian ELTS), allowlist the finding with that reason |
| UPD-005 | Low             | Security updates are not installed automatically: unattended-upgrades missing or off (apt), no dnf-automatic, dnf5-automatic or yum-cron timer that applies updates (dnf, yum). Allowlist it where updates roll out another way |

Update checks only read the package manager's local cache. Nöbet never refreshes metadata or installs anything; when there is no cache to read, the check is skipped and tells you which command would create one.

FS-004 looks in every account's `~/.ssh`, at every key an ssh configuration names (`IdentityFile` in `/etc/ssh/ssh_config`, its `.d` directory and each account's `~/.ssh/config`, so a backup job's key in `/etc/backup` counts), in the `.ssh` directories of applications under `/opt` and `/srv`, at `/etc/ssh/ssh_host_*_key`, and in `/etc/ssl/private`, `/etc/pki/tls/private` and `/etc/letsencrypt/archive`. A key counts as readable when its permissions and those of every directory above it let the account in: a key with mode 644 in a home of mode 700 is safe. ACLs count as the kernel applies them (a named entry for the account, then its groups, with the mask), so a key that `setfacl -m u:bob:r` opens to bob is reported "through an ACL". Only the key's first line (its PEM header) is read on the host, and its public fingerprint taken from the `.pub` file or from the public part an OpenSSH-format key carries; key material never leaves the host. In the root access map, a key whose private half others can read on some host is marked with `!` and where, since everyone who can read it gets every route to root the key has, on every host.

FS-005 looks for those files in every account's home, `.env` files of applications under `/opt`, `/srv` and `/var/www`, WordPress configs there, and a few system files (`/etc/mysql/debian.cnf`, mail relay passwords, and the password hash files, which count only when they hold a hash rather than just locked entries). The content is checked on the host (a `.my.cnf` with only a user name, or a Docker config that defers to a credential helper, does not count), and only the path and what it is come back. Only files every account can read are reported: a web server's group reading its site's config is by design.

FS-003 follows what root runs: root's cron jobs (`/etc/crontab`, `/etc/cron.d`, root's crontab, anacron, and the scripts in `/etc/cron.daily` and the like or Alpine's `/etc/periodic`), systemd services that run as root (unit files, drop-ins and every `Exec` command) and the `+` or `!` commands of services that run as another user, root's shell startup files, the directories on root's PATH (the standard ones, `/etc/environment` and sudo's `secure_path`), the programs sudo rules let someone run as root, and the account, sudo and dynamic loader configuration. For scripts outside the package-managed directories, the `#!` interpreter counts too (a cron script that runs `/opt/app/venv/bin/python` is only as safe as that virtualenv), and so do the files the script runs or sources by absolute path. Those are found on the host by awk; only paths leave it, never script contents. From each command line it takes the programs and the scripts given to interpreters (`php /var/www/app/artisan`, `sh -c '...'`), not arguments or redirections, and leaves out commands that switch to another user (`sudo -u`, `su`). A file counts as changeable by an account that owns it or can write it (through its group or an ACL entry), or that can write any directory above it (a sticky directory like `/tmp` protects what is already in it); symlinks are followed. The accounts found show up in the root access map, which lists up to three such files per account.

Ports that Docker publishes (`-p 8080:80`) are reachable from the network even when ufw (or firewalld, or INPUT rules of your own) denies them: Docker forwards them to the container in its own NAT rules, before the firewall's input rules see them. NET-002 lists them when a firewall is active and Docker's `DOCKER-USER` chain, where such ports can be filtered, is empty; a database among them is a High NET-001 finding. Publish ports that need not be public on `127.0.0.1` (`-p 127.0.0.1:8080:80`), or filter them in `DOCKER-USER`.

NET-003 reads the kernel NFS server's export table (`/var/lib/nfs/etab`, which `exportfs -ra` writes and stopping the server empties) rather than `/etc/exports`, so it sees what is exported now, with every default filled in; a server that is not running exports nothing. With the usual `sec=sys`, the server takes the client's word for which account is asking: root on a client can act as any account but root on every export, and as root where root is not squashed. On exports to named hosts that is how NFS works, so only root access is reported there, and only for writing (a backup host reading everything as root is common). On exports every host may mount, anyone who controls a machine on the network can do the same, so reading and writing as any account are reported too.

CTR-001 reads root's running containers with `docker inspect` and `podman inspect`, naming the fields it needs, so the containers' environment (often holding passwords) never leaves the host. A control socket counts whether it is mounted read-only or not, and whether the socket itself or a directory above it (`/run`, `/var/run`, `/`) is mounted; only sockets that exist on the host count. Monitoring agents and reverse proxies often need the Docker socket: give them a socket proxy that allows only the calls they need, or allowlist them by container name (`CTR-001 * traefik`). podman is only asked where it has been used before, since `podman ps` on a fresh install would set up its storage.

Incus and LXD containers are found from their running `[lxc monitor]` processes, and each one's configuration is read from the `backup.yaml` its daemon keeps, through the monitor's view of the file system (which also reaches snap LXD's own). The `incus` and `lxc` commands are not used: the snap's would set up files in root's home. Only the settings that matter leave the host, never `environment.*` values. Root in an unprivileged container is an unprivileged account on the host, so a host directory passed in only counts when it is shifted (`shift=true`, which lets the container's root write as the host's root); in a privileged container every host directory counts, as for Docker. Block and character devices count either way.

LOG-001 uses the same messages to tell whether you could find out, after the fact, who logged in: they should reach back 90 days. Short logs are only reported on a system older than they are (from the root file system's creation, `/etc/machine-id`, which a cloud VM writes at its first boot, or the `basesystem` package), so a new server does not get the finding; when the age cannot be told, the check says so.

ACC-006 reads sshd's "Accepted publickey" messages, which name the key, from the journal and from `/var/log/auth.log`, `secure` and `messages` (rotated and gzipped copies included); only times, account names and key fingerprints leave the host. A key line counts as used when any account that reads that file logged in with it. It needs logs that reach back 90 days; when some key has no recent login and the logs are shorter (RHEL keeps its journal in memory and four weeks of `/var/log/secure` by default), the check is skipped and says how far back they go. A persistent journal (`mkdir -p /var/log/journal`) fixes that. Keys kept for emergencies can be allowlisted by fingerprint. The root access map shows each key's last login too.

UPD-004 knows Ubuntu, Debian (including its free LTS period) and Raspbian, RHEL, Rocky Linux, AlmaLinux, CentOS and CentOS Stream, Oracle Linux, Fedora, Alpine, openSUSE Leap, SLES and Amazon Linux. Support dates come from [endoflife.date](https://endoflife.date) and are built into each release; nöbet does not go online for them. Rolling releases are skipped. Nöbet never refreshes metadata or installs anything; when there is no cache to read, the check is skipped and tells you which command would create one.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above `-fail-on` |
| 1 | At least one finding at or above `-fail-on` (default: high) |
| 2 | Usage error |
| 3 | No failing findings, but some hosts could not be scanned |

## Known limitations

- sshd's effective config comes from `sshd -T`, with the `-o` options the running daemon was started with (RHEL 8 and its rebuilds pass the system crypto policy that way). Other command-line options of the running daemon, such as `-f` for another config file, are not followed.
- sshd `Match` blocks are evaluated with `sshd -T -C` for the accounts that can become root (and for an arbitrary account), connecting from anywhere and from one sample address per `Match Address` entry. `Match Host`, `LocalAddress` and `LocalPort` criteria and IPv6 address wildcards are not sampled, and keys are always read from the global `AuthorizedKeysFile`.
- The account you scan with will show up in ACC-002 if it has passwordless sudo; add it to the allowlist.
- `user@host` patterns in `AllowUsers` are treated as allowing the user from anywhere.
- Shell-escape detection for limited sudo rules uses a built-in list of well-known programs; a custom script that runs other commands is not inspected (though FS-003 reports it when someone other than root can change it).
- FS-003 checks the files that command lines name with a path, script interpreters, the directories on root's PATH, and what those scripts run or source by absolute path, one level deep. Paths built from variables, and libraries, are not followed.
- sudo Defaults are honored as `sudo -l` reports them, for the user, per runas user (`Defaults>root targetpw`) and per command (`Defaults!/usr/bin/vim rootpw`); host-bound Defaults are taken as already applied by sudo.
- SUID and world-writable checks search /bin, /sbin, /usr, /opt, /etc, /tmp, /var/tmp, /home, /root and /srv, without crossing filesystems; the rest of /var is skipped because container storage holds many copies of SUID binaries.
- ACC-006 trusts only journal entries from root's sshd processes, which no other account can fake. Syslog files cannot tell sshd's messages from ones any local account writes with `logger`, so on hosts without a journal (Alpine, or the time before the journal begins) a local account could make a key look used. Keys from `AuthorizedKeysCommand` are not listed, so ACC-006 cannot check them; a certificate login counts as a use of its CA's `cert-authority` line.
- FS-004 only searches the places listed above; a key that only a script passes with `ssh -i` is not found unless an ssh configuration names it.
- FS-003 and FS-004 read ACLs with `getfacl`, which comes with the `acl` package (the tool that sets them); on a host without it, ACLs are not seen. A file every account can read by its mode is still reported that way when an ACL shuts out a few accounts. FS-005 only reports what every account can read, which ACLs cannot widen.
- The Docker API check reads root's dockerd command line, `DOCKER_TLS_VERIFY` in its environment and `daemon.json`. A TCP socket that systemd hands to dockerd (`-H fd://` with a `ListenStream=` port in `docker.socket`) is only seen when it is port 2375.
- Any rule in Docker's `DOCKER-USER` chain counts as published ports being filtered there; the rules themselves are not evaluated.
- CTR-001 looks at root's Docker daemon, root's podman, and Incus and LXD. Kubernetes pods (containerd and CRI-O without Docker) and plain LXC containers (`lxc-start`) are not listed. Rootless containers are left out on purpose: they run as their account, so they cannot reach more of the host than that account can. For Docker and podman it assumes root in a container is root on the host, which Docker's `userns-remap` changes. For Incus and LXD, `raw.lxc` and `raw.idmap` settings are not evaluated.
- NET-003 reads the kernel NFS server's exports; NFS-Ganesha and Samba shares are not looked at. Wildcard host names (`*.example.com`) and netgroups count as named hosts, and `0.0.0.0/0` as a network (nfs-utils 2.8.3 matches no client with it; `*` and `0.0.0.0/0.0.0.0` match every one).
- Local scanning is Linux-only; from macOS or Windows, scan hosts over SSH.

## Roadmap

- [x] TUI: live progress, host list, findings pane, severity filter
- [x] `nobet rootmap`: who can become root on which host, and how (SSH keys, sudo, groups)
- [x] rootmap view in the TUI (press `r`)
- [x] Drift: compare with the previous scan and show what changed (`nobet diff`)
- [x] Allowlist for reviewed findings
- [x] Pending security updates and reboot-required (apt, dnf, dnf5, yum, zypper; all pending updates for apk)
- [x] Firewall status, SUID binaries, world-writable paths
- [x] `~/.ssh/config` support (aliases, users, ports, keys, ProxyJump chains)
- [x] HTML and PDF reports for auditors (`-html`, `-pdf`)
- [x] First tagged release, v0.1.0 (see CHANGELOG.md)
- [x] Follow custom `AuthorizedKeysFile` and `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups` in rootmap
- [x] Flag limited sudo rules that allow shell escapes (GTFOBins)
- [x] ssh-agent on Windows (OpenSSH named pipe)
- [x] Evaluate sshd `Match` blocks (`sshd -T -C`)
- [x] Password states from `/etc/shadow` (empty passwords, locked accounts in rootmap)
- [x] Listening sockets without `ss` (reads /proc/net)
- [x] sudo `rootpw`/`targetpw`/`!authenticate` in rootmap, including per-user, per-runas and per-command Defaults
- [x] Docker Compose deployment (scanner + read-only dashboard)
- [x] Signed releases with SBOMs; signed multi-arch container images on ghcr.io
- [x] OS end of support (UPD-004), with Ubuntu Pro ESM detection
- [x] Automatic security updates (UPD-005)
- [x] Kernel hardening settings (KRN-001)
- [x] Files root runs that other accounts can change (FS-003), as routes in the root access map
- [x] Key owners and offboarding (`-keys`, `nobet rootmap -who`)
- [x] Weak SSH algorithms (SSH-005), with RHEL 8's crypto policy taken into account
- [x] Alerts on changes (`-on-change` hooks) and Prometheus metrics (`nobet-web -metrics`)
- [x] Ansible inventories (INI, and `ansible-inventory --list` JSON) with `-group`
- [x] `nobet-web`: read-only team dashboard over a shared scan history
- [x] `nobet-web`: built-in OIDC sign-in with a read-only role, and an audit log of who viewed what
- [x] PDF reports (`-pdf`, and HTML/PDF downloads in the dashboard)
- [x] Scans asked for from the dashboard, run by the scanner account through a queue
- [x] Reports from saved scans (`nobet report`), changes over a period (`nobet diff -since`), findings by check in the dashboard
- [x] SSH keys that have not logged in for 90 days (ACC-006), and each key's last login in the root access map
- [x] Containers that can take over the host (CTR-001): Docker and podman, Incus and LXD
- [x] Private keys other accounts can read (FS-004), marked in the root access map
- [x] Credential files every account can read (FS-005)
- [x] NFS exports that give away root or every account's files (NET-003)
- [x] ACLs in FS-003 and FS-004 (who can change files root runs, who can read private keys)
- [x] Login records kept for 90 days (LOG-001)
- [x] Weak password hashes (ACC-007)

## Project layout

```
cmd/nobet/          CLI entry point and subcommands
cmd/nobet-web/      read-only dashboard (separate binary)
internal/runner/    the Runner interface collectors use
internal/transport/ command execution: local (/bin/sh) and SSH
internal/collect/   gathers facts through a runner
internal/checks/    evaluates facts into findings
internal/scan/      scan results and evaluation
internal/fleet/     local and parallel remote scans (CLI only)
internal/web/       dashboard pages, templates and styles
internal/rootmap/   fleet-wide root access map
internal/allow/     allowlist of reviewed findings
internal/store/     saved scan history
internal/drift/     changes between scans
internal/brand/     terminal logo
internal/report/    text, JSON and HTML output
internal/tui/       interactive terminal UI (Bubble Tea)
internal/inventory/ host list parsing
internal/sshconf/   ~/.ssh/config resolution (aliases, ProxyJump)
contrib/systemd/    units for a nightly scan and the dashboard
contrib/docker/     the scanner image's scan loop (Dockerfile and compose.yaml are at the top level)
```

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
