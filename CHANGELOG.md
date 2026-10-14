# Changelog

## v0.1.0 — first release

nöbet audits Linux servers over SSH, or the machine it runs on, without installing anything on them.

**Scanning**
- `nobet scan`: local machine, hosts on the command line, or an inventory file; parallel, read-only, strict host key checking.
- Resolves hosts through `~/.ssh/config` (or a file given with `-F`): aliases, users, ports, identity files and `ProxyJump` chains.
- Uses ssh-agent on Linux, macOS and Windows (OpenSSH Authentication Agent named pipe).
- Interactive TUI with live progress, per-host findings, a severity filter and a fleet-wide root access view; plain text and JSON for scripts and CI.
- HTML report for auditors (`-html`), self-contained and print-ready.
- Exit codes for automation (`-fail-on`).

**Checks**
- SSH: root login, password and keyboard-interactive auth, empty passwords, X11 forwarding.
- Access: extra UID 0 accounts, passwordless sudo, limited sudo rules that escape to a root shell (GTFOBins), root-equivalent groups (docker, lxd, incus), accounts with empty passwords.
- SSH checks and rootmap evaluate `Match` blocks and say where a setting applies (`from 10.0.0.0/8`, `for deploy`).
- Network: databases and admin APIs on all interfaces, missing host firewall.
- Updates: pending security updates (apt, dnf, dnf5, yum, zypper; every pending update for apk, which does not label security fixes), reboot required, stale package indexes for every manager.
- Files: SUID shells and interpreters, SUID files in temporary or home directories or outside any package, world-writable system paths.

**Access and change tracking**
- `nobet rootmap`: who can become root on which host and how, grouped by SSH key; follows `AuthorizedKeysFile`, applies `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups`, account password states, and sudo's `rootpw`/`targetpw`/`!authenticate` Defaults per user, runas user and command.
- `nobet diff`: what changed since the previous scan (root routes, keys, accounts, password states, group memberships, SUID files, sshd settings, firewall, ports, findings).
- Allowlist for reviewed findings, with reasons kept for audits.
- Shared scan history: `-history-dir` or `NOBET_DATA_DIR`, with group-readable files in a directory an admin prepared for it.

**Team dashboard (`nobet-web`, separate package)**
- Read-only view of a shared scan history: fleet status and 30-day trend, each host's findings, allowlist decisions, skipped checks and scan history, all changes between scans, and the root access map.
- Never scans and holds no SSH keys; the build is tested to contain no SSH client. No login of its own: listens on localhost behind your authenticating reverse proxy, and can log the user the proxy reports.
- Strict Content-Security-Policy (no scripts at all), no caching of pages, GET/HEAD only.
- systemd units for a nightly scan under a service account and for the dashboard, in `contrib/systemd`.
- Docker Compose: a scanner container that holds the SSH key and a distroless, read-only dashboard container (`compose.yaml`).

**Scale**
- 50 hosts scan in about 10 seconds; history is read one scan at a time, so `nobet diff`, the post-scan summary and the dashboard stay around 25-30 MB even with 100 saved scans of 50 hosts.

**Known limitations**
- `ProxyCommand` is not supported; use `ProxyJump`.
- `Match Host`, `LocalAddress` and `LocalPort` criteria are not sampled; keys from `AuthorizedKeysCommand` and user certificates are reported as gaps rather than listed.
