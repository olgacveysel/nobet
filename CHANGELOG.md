# Changelog

## Unreleased

- ACC-006: authorized SSH keys that have not logged in for 90 days, from sshd's "Accepted publickey" messages in the journal and the syslog files (rotated and gzipped ones too); Medium when the key reaches an account that can become root. Only journal entries from root's sshd are trusted, so no local account can make a key look used there. When the logs do not reach back 90 days, the check says how far they go instead of guessing.
- The root access map (text, TUI, HTML, PDF and the dashboard) shows when each key last logged in as each account.
- FS-003 no longer reports masked systemd services: their unit file is a link to /dev/null, which anyone can write to, but systemd never starts them.
- `nobet report -pdf FILE` (and/or `-html FILE`): the reports from the saved history, without scanning, from each host's newest successful scan; `-host` narrows it. For a weekly report from cron.
- `nobet diff -since 7d` (`2w`, `36h`): what changed since each host's newest scan from before then, rather than since the previous scan.
- nobet-web: "Findings by check" on the fleet page, and a page per check (`/check/SSH-001`) with every host it fires on, where it is allowlisted and why, and where it could not run; check IDs on host pages link to it.
- Binaries built with `go install …@v0.1.0` report their version (`nobet 0.1.0`) instead of `dev`.
- Release workflow: builds the tag it was started for even when two tags share a commit (v0.1.0-rc1 and v0.1.0 did, and the first v0.1.0 run picked rc1), and can rebuild an existing tag's release by hand (`gh workflow run release -f tag=vX.Y.Z`). Such runs are signed as `release.yml@refs/heads/master`; the verify commands in the README accept both. A run for a tag that is already released stops at the start instead of failing after the build.

## v0.1.0 — 2026-10-21

The first release. nöbet audits Linux servers over SSH, or the machine it runs on, without installing anything on them.

**Scanning**
- `nobet scan`: local machine, hosts on the command line, or an inventory file; parallel, read-only, strict host key checking.
- Reads Ansible inventories with `-i`: INI files (groups, children, vars, host ranges, `ansible_host`/`ansible_port`/`ansible_user`) and the JSON of `ansible-inventory --list` for YAML and dynamic ones; `-group` picks groups.
- Resolves hosts through `~/.ssh/config` (or a file given with `-F`): aliases, users, ports, identity files and `ProxyJump` chains.
- Uses ssh-agent on Linux, macOS and Windows (OpenSSH Authentication Agent named pipe).
- Interactive TUI with live progress, per-host findings, a severity filter and a fleet-wide root access view; plain text and JSON for scripts and CI.
- HTML and PDF reports for auditors (`-html`, `-pdf`).
- Exit codes for automation (`-fail-on`).

**Checks**
- SSH: root login, password and keyboard-interactive auth, empty passwords, X11 forwarding, weak or deprecated algorithms (SSH-005). The effective config includes the running sshd's `-o` options, so RHEL 8's crypto policy counts.
- Access: extra UID 0 accounts, passwordless sudo, limited sudo rules that escape to a root shell (GTFOBins), root-equivalent groups (docker, lxd, incus), accounts with empty passwords.
- SSH checks and rootmap evaluate `Match` blocks and say where a setting applies (`from 10.0.0.0/8`, `for deploy`).
- Network: the Docker API without TLS on any non-loopback address (Critical), databases and admin APIs on all interfaces, missing host firewall.
- Updates: pending security updates (apt, dnf, dnf5, yum, zypper; every pending update for apk, which does not label security fixes), reboot required, stale package indexes for every manager.
- Automatic security updates off (UPD-005): unattended-upgrades, dnf-automatic, dnf5-automatic and yum-cron.
- OS end of support (UPD-004): past or within 180 days, for 13 distributions, with Ubuntu Pro ESM detected; dates from endoflife.date, built in.
- Kernel hardening (KRN-001): ASLR, symlink and hardlink protection, setuid core dumps, SYN cookies, source routing.
- Files: SUID shells and interpreters, SUID files in temporary or home directories or outside any package, world-writable system paths.
- Files root runs that other accounts can change (FS-003): cron jobs, run-parts scripts, systemd services running as root (and `+`/`!` commands of other services), root's shell startup files and PATH directories, script interpreters and what scripts run or source, programs named in sudo rules, and account/sudo/loader configuration; each account found is a route in `nobet rootmap`.

**Access and change tracking**
- `nobet rootmap`: who can become root on which host and how, grouped by SSH key; follows `AuthorizedKeysFile`, applies `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`, account password states, and sudo's `rootpw`/`targetpw`/`!authenticate` Defaults per user, runas user and command.
- Key owners (`-keys`, `~/.config/nobet/keys`): the root access map names who each key belongs to and flags keys with root access that nobody claims; `nobet rootmap -who alice` lists everything to revoke when someone leaves.
- `nobet diff`: what changed since the previous scan (root routes, keys, accounts, password states, group memberships, SUID files, sshd settings, firewall, ports, findings).
- Allowlist for reviewed findings, with reasons kept for audits; `nobet checks` lists the check IDs.
- `nobet scan -on-change CMD`: runs a hook when a scan finds changes, with them as JSON on stdin and a short summary in the environment; `contrib/hooks/slack` posts to a Slack or Mattermost webhook.
- Shared scan history: `-history-dir` or `NOBET_DATA_DIR`, with group-readable files in a directory an admin prepared for it.

**Team dashboard (`nobet-web`, separate package)**
- Read-only view of a shared scan history: fleet status and 30-day trend, each host's findings, allowlist decisions, skipped checks and scan history, all changes between scans, and the root access map.
- Never scans and holds no SSH keys; the build is tested to contain no SSH client. Listens on localhost behind your authenticating reverse proxy (and can log the user the proxy reports), or signs users in itself (below).
- Strict Content-Security-Policy (no scripts at all), no caching of pages; GET/HEAD only, apart from the opt-in scan request form.
- Report downloads (HTML and PDF) from each host's newest scan.
- "Scan now" (`-scan-queue`): users ask for a scan of every host or one host; nobet-web only writes a request, and `nobet scan -queue` (systemd path unit, or the Docker scanner) runs it as the scanner account. Off by default; `-scan-users`/`-scan-groups` say who may ask.
- Built-in sign-in with OpenID Connect (`-oidc-issuer`): authorization code flow with PKCE, allowed users or groups (nobody by default), signed session cookies; or keep using an authenticating proxy.
- Audit log (`-audit-log`): one JSON line per page view, sign-in, refusal and sign-out, with the user.
- HTTPS (`-tls-cert`, `-tls-key`), and metrics on a separate listener (`-metrics-listen`).
- Optional Prometheus metrics (`-metrics`): findings per host and severity, scan times, stale and unreachable hosts, SSH keys with root access.
- Key owners on the root access page (`-keys`).
- systemd units for a nightly scan under a service account and for the dashboard, in `contrib/systemd`.
- Docker Compose: a scanner container that holds the SSH key and a distroless, read-only dashboard container (`compose.yaml`).

**Releases**
- Binaries for Linux, macOS and Windows; `nobet` and `nobet-web` deb, rpm and apk packages.
- An SPDX SBOM per archive, and a keyless Sigstore signature over `checksums.txt`.
- Container images on ghcr.io (`nobet-scanner`, `nobet-web`) for amd64 and arm64, signed, with SBOM and build provenance; `compose.yaml` uses them and can pin a version (`NOBET_VERSION`).

**Scale**
- 50 hosts scan in about 10 seconds; history is read one scan at a time, so `nobet diff`, the post-scan summary and the dashboard stay around 25-30 MB even with 100 saved scans of 50 hosts.

**Known limitations**
- `ProxyCommand` is not supported; use `ProxyJump`.
- `Match Host`, `LocalAddress` and `LocalPort` criteria are not sampled; keys from `AuthorizedKeysCommand` and user certificates are reported as gaps rather than listed.
