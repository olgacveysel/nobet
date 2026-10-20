<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo/nobet-owl-wordmark.svg">
    <img alt="nöbet" src="docs/logo/nobet-owl-wordmark-light.svg" width="380">
  </picture>
</p>

# Nöbet (`nobet`)

**Your servers' night watch.** Nöbet audits the security of Linux servers, either the machine it runs on or remote hosts over SSH: SSH configuration, root and sudo access, exposed services and more. It is built for small teams (up to roughly 50 servers) that want answers without deploying agents or a SIEM.

*Nöbet* is Turkish for a watch or guard shift.

> Status: early development (v0.1).

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

Releases after v0.1.0-beta.1 come with an SPDX SBOM per archive (`*.sbom.json`) and a signed `checksums.txt`. The signature is keyless ([Sigstore](https://www.sigstore.dev/)): it proves the file was made by this repository's release workflow for a tag, and it is recorded in a public transparency log. With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/):

```bash
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/olgacveysel/nobet/\.github/workflows/release\.yml@refs/tags/v' \
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

Run `nobet help scan` for all flags. Flags must come before host arguments.

Hosts are resolved through `~/.ssh/config` and `/etc/ssh/ssh_config` like `ssh` does: aliases (`HostName`), `User`, `Port`, `IdentityFile` and `ProxyJump` (including chains such as `ProxyJump gw1,bastion`). Values you give explicitly (`user@host:port`, `-u`) win over the config. Use `-F <file>` (`-ssh-config`) to read one config file instead, like `ssh -F`, or `-no-ssh-config` to ignore it. `ProxyCommand` is not supported; hosts that need it are reported with a clear error.

`-i` also reads Ansible inventories: INI files directly (groups, `:children`, `:vars`, host ranges like `web[01:10]`, and `ansible_host`, `ansible_port` and `ansible_user`, with Ansible's precedence), and YAML or dynamic inventories through the JSON that `ansible-inventory -i inventory.yml --list > inventory.json` prints. Hosts keep their inventory names in reports, `-group` picks groups (children included), and hosts with `ansible_connection=local` are skipped (use `-local`).

Keys come from ssh-agent (`SSH_AUTH_SOCK`; on Windows the OpenSSH Authentication Agent service is used automatically), the config's `IdentityFile`s, and unencrypted keys in `~/.ssh` or given with `-identity`.

Short forms: `nobet s` for `scan`, `nobet r` for `rootmap`, `nobet d` for `diff`, `nobet -v` for `version` and `nobet -h` for `help`. Common flags also have one-letter forms: `-j` (`-json`), `-p` (`-plain`), `-l` (`-local`), `-f` (`-fail-on`) `-t` (`-timeout`) and `-F` (`-ssh-config`).

### Root access map

```bash
nobet rootmap -i hosts.txt
```

`rootmap` answers "who can become root on which host, and how?" across your whole fleet. It combines every account's authorized SSH keys with its routes to root: direct UID 0 login (respecting `PermitRootLogin`), `sudo ALL` as resolved by sudo itself (`sudo -l -U`, so aliases, includes and LDAP rules count), limited sudo rules that escape to a shell (`sudo vim`, `sudo less`, `sudo find`, see [GTFOBins](https://gtfobins.github.io)), root-equivalent groups, and files root runs that the account can change (a cron job's script in a directory it owns, a service binary it can write, the program a sudo rule names; see FS-003). Keys are read from the files sshd's `AuthorizedKeysFile` names, and a key only counts when sshd lets its account log in with it (`PubkeyAuthentication`, `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`). `Match` blocks count too: a route or key that sshd allows only from some networks says so (`UID 0 login from 10.0.0.0/8`). Password states from `/etc/shadow` and sudo's own Defaults refine the routes: a sudo rule that asks for a locked password, or for root's password (`rootpw`, `targetpw`, as on openSUSE), is no route at all, and one that asks for an empty password (or none, `!authenticate`) is free. Keys that come from `AuthorizedKeysCommand` or user certificates (`TrustedUserCAKeys`) cannot be listed; they are reported under INCOMPLETE. Results are grouped by SSH key, so a single key that opens root on many hosts stands out:

```
ROOT ACCESS BY SSH KEY

SHA256:tnsW9C5r…  ed25519  veysel@laptop
  root on 3 host(s):
    web01  as deploy  via sudo ALL, no password
    web02  as root    via UID 0 login
    db01   as ops     via docker group  [only from "10.0.0.5"]

ROOT-CAPABLE ACCOUNTS WITHOUT SSH KEY ACCESS
    web02  backup  via sudo ALL, password required

INCOMPLETE
    db02   not scanned: connection refused
```

Use `-json` for machine-readable output. Full results need root or passwordless sudo on every host.

#### Key owners and offboarding

A key comment like `veysel@laptop` is whatever someone typed. To have the map name people reliably, list who owns which key in `~/.config/nobet/keys` (or pass `-keys FILE`; see [keys.example](keys.example)):

```
alice  SHA256:52JZmNfuKifllhTBswzRjmhmtxlcsa2aXf71Sl853cQ   # laptop
alice  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... alice@desktop
ci     SHA256:HRmMEMU9cyejr7STBxyzzOI4cfmC7Xkho7aTuOfNdNA   # deploy pipeline
```

Each key is then labelled with its owner, and keys that lead to root without an owner in the file are counted and marked `(no known owner)`. The same file names owners in the TUI's root view, the HTML report and `nobet-web -keys`. When someone leaves:

```bash
nobet rootmap -i hosts.txt -who alice
```

lists every host where Alice's keys reach root, any other key that reaches an account named `alice`, and `alice` accounts that can become root without a key. Without a keys file, `-who` matches key comments (`alice` or `alice@...`) instead.

### HTML report

```bash
nobet scan -p -i hosts.txt -html report.html
```

Writes a single self-contained HTML file (no external scripts, fonts or images) with a severity summary, every host's findings with fixes, allowlisted findings with their reasons, skipped checks, and the root access map. It prints cleanly to PDF for auditors. The file is created with mode 0600 because it describes weaknesses and access paths.

In the TUI, press `r` to switch to the root access map for the hosts scanned so far.

### Allowlist

Some findings are expected: your scanning account needs passwordless sudo, web servers listen on 443. Put reviewed exceptions in `~/.config/nobet/allowlist` (or pass `-allow <file>`), one rule per line:

```
# <check-id>  <host-glob>  [text to match]   # reason
ACC-002  *     nobet-scan   # scanning account needs passwordless sudo
NET-001  web*  tcp/443      # public web servers
*        lab-*              # lab machines are out of scope
```

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

For complete remote results, the SSH user should be root or have passwordless sudo, because reading the effective sshd config and sudoers requires root. Without it, those checks are reported as skipped.

## Team dashboard: `nobet-web`

`nobet-web` is a separate, optional binary and package that shows the scan history to your team in a browser: fleet status with a 30-day trend, each host's findings and scan history, every change between scans, and the root access map.

**It is read-only by design.** It never scans, never connects to your servers and holds no SSH keys (its build is tested to contain no SSH client at all). A systemd timer runs `nobet scan` under a service account and saves to a shared history directory, which the dashboard only reads. If the dashboard were compromised, an attacker would learn your weaknesses but could not act on them.

**It has no login of its own.** It listens on `127.0.0.1:8080` and belongs behind a reverse proxy that authenticates your team (oauth2-proxy, Authelia, Authentik, Pomerium or your SSO). If the proxy passes the signed-in user in a header, add `-user-header X-Forwarded-User` (or `Remote-User`, ...) to log who viewed which page. `-keys /etc/nobet/keys` names key owners on the root access page (the file is read on every view). The root access map shows which key opens which server, so never expose the dashboard directly.

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

#### Prometheus metrics

`nobet-web -metrics` also serves `/metrics` for a Prometheus on the same machine (or one your proxy lets through): per host, the findings in its newest successful scan by severity (`nobet_host_findings`), allowlisted findings, whether the newest attempt succeeded (`nobet_host_up`), whether it is stale (`nobet_host_stale`), the scan times and whether the scan was privileged; for the fleet, the number of SSH keys that lead to root (`nobet_root_keys`, and `nobet_root_keys_unclaimed` with `-keys`). For example:

```yaml
groups:
  - name: nobet
    rules:
      - alert: NobetCriticalFinding
        expr: nobet_host_findings{severity="critical"} > 0
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

Compose runs the release images `ghcr.io/olgacveysel/nobet-scanner` and `ghcr.io/olgacveysel/nobet-web` (amd64 and arm64). Pin a version with `NOBET_VERSION=0.1.0` in a `.env` file next to `compose.yaml` (the default is `latest`, which only moves on releases, not pre-releases); `docker compose up -d --build` builds both from the checkout instead. The images are signed the same way as the downloads, and carry an SBOM and build provenance:

```bash
cosign verify ghcr.io/olgacveysel/nobet-web:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/olgacveysel/nobet/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/olgacveysel/nobet-web:0.1.0 --format '{{ json .SBOM }}'
```

### Scale

Measured with 50 hosts (the size nöbet is built for): a full scan takes about 10 seconds at the default concurrency (`-c 10`) and under 30 MB of memory. With the maximum history of 100 such scans (about 75 MB on disk), `nobet diff` takes 0.4 seconds and the dashboard uses about 25 MB; both read the history one scan at a time.

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
| NET-001 | Critical / High / Info | The Docker API without TLS (port 2375) on any non-loopback address (Critical: root for anyone who can connect); databases and admin APIs listening on all interfaces |
| NET-002 | Medium / Low    | No host firewall filtering incoming traffic (ufw, firewalld, nftables, iptables); Medium when services are exposed |
| FS-001  | Critical / High / Medium | SUID on programs that spawn a root shell (bash, find, vim, python…), SUID files in /tmp or home directories, SUID files not owned by any package |
| FS-002  | High            | World-writable files, or world-writable directories without the sticky bit, in /etc, /usr, /bin, /sbin, /opt |
| FS-003  | Critical / High | Files root runs or trusts that other accounts can change: Critical when anyone can, High when named accounts can (see below) |
| UPD-001 | High / Medium   | Pending security updates (apt, dnf, dnf5, yum, zypper); High when the vendor rates any as critical or important. apk (Alpine) does not label security fixes, so there every pending update is reported, as Medium |
| UPD-002 | Medium          | Reboot required: newer kernel installed than running, or a reboot flag file exists |
| UPD-003 | Low             | Package indexes not refreshed for more than 7 days, so update counts may be incomplete (all supported package managers) |
| UPD-004 | High / Low / Info | The OS release is past its end of support (High) or reaches it within 180 days (Low). Ubuntu hosts with Ubuntu Pro ESM (esm-infra) enabled are Info until ESM ends; for paid extended support elsewhere (RHEL ELS, SLES LTSS, Debian ELTS), allowlist the finding with that reason |

Update checks only read the package manager's local cache. Nöbet never refreshes metadata or installs anything; when there is no cache to read, the check is skipped and tells you which command would create one.

FS-003 follows what root runs: root's cron jobs (`/etc/crontab`, `/etc/cron.d`, root's crontab, anacron, and the scripts in `/etc/cron.daily` and the like or Alpine's `/etc/periodic`), systemd services that run as root (unit files, drop-ins and every `Exec` command), root's shell startup files, the programs sudo rules let someone run as root, and the account, sudo and dynamic loader configuration. From each command line it takes the programs and the scripts given to interpreters (`php /var/www/app/artisan`, `sh -c '...'`), not arguments or redirections, and leaves out commands that switch to another user (`sudo -u`, `su`). A file counts as changeable by an account that owns it or can write it, or that can write any directory above it (a sticky directory like `/tmp` protects what is already in it); symlinks are followed. The accounts found show up in the root access map, which lists up to three such files per account.

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
- FS-003 checks the files that command lines name with a path. Programs found through `PATH` are covered by checking the `PATH` directories a crontab sets, not root's own `PATH`; files a script sources or runs in turn, and libraries, are not followed.
- sudo Defaults are honored as `sudo -l` reports them, for the user, per runas user (`Defaults>root targetpw`) and per command (`Defaults!/usr/bin/vim rootpw`); host-bound Defaults are taken as already applied by sudo.
- SUID and world-writable checks search /bin, /sbin, /usr, /opt, /etc, /tmp, /var/tmp, /home, /root and /srv, without crossing filesystems; the rest of /var is skipped because container storage holds many copies of SUID binaries.
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
- [x] HTML report for auditors (`-html`)
- [ ] First tagged release, v0.1.0 (see CHANGELOG.md)
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
- [x] Files root runs that other accounts can change (FS-003), as routes in the root access map
- [x] Key owners and offboarding (`-keys`, `nobet rootmap -who`)
- [x] Weak SSH algorithms (SSH-005), with RHEL 8's crypto policy taken into account
- [x] Alerts on changes (`-on-change` hooks) and Prometheus metrics (`nobet-web -metrics`)
- [x] Ansible inventories (INI, and `ansible-inventory --list` JSON) with `-group`
- [x] `nobet-web`: read-only team dashboard over a shared scan history
- [ ] `nobet-web`: built-in OIDC login with a read-only role, and an audit log of who viewed what

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
