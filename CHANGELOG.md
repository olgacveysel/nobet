# Changelog

## Unreleased

- NET-001 reads root's dockerd settings (command line, `DOCKER_TLS_VERIFY`, `daemon.json`) and reports its API open to clients without a certificate on any port: TCP without TLS, or TLS with `tlsverify=false` (Critical; High when bound to loopback). Before, only a listener on port 2375 was caught; it still is where the settings cannot be read. Checked against dockerd 29.9: `--tls` alone verifies client certificates, `tlsverify=false` does not.
- FS-005 reports password hashes every account can read: `/etc/shadow`, `/etc/gshadow`, their backups (`shadow-`, `/var/backups/shadow.bak`), `/etc/security/opasswd`, and hashes left in `/etc/passwd`. Files with only locked or disabled entries do not count; the hashes never leave the host.

## v0.4.0 — 2026-10-27

More ways in that a server can leave open: credential files anyone can read, NFS exports that hand out root, Incus and LXD containers, and permissions granted through ACLs.

**New checks**
- FS-005: credential files every account can read (`.pgpass`, `.my.cnf`, `.netrc`, `.git-credentials`, AWS, Docker registry, Kubernetes, GitHub CLI, npm, PyPI, Vault, S3, rclone and Google Cloud credentials, application `.env` files, WordPress configs, mail relay passwords). The content is checked on the host and never leaves it.
- NET-003: NFS exports that give away root or every account's files. Root on a client is root in a writable export (`no_root_squash`, `anonuid=0`): Critical when every host may mount it, High for named hosts; exports every host may mount are also reported for reading as root or reading and writing as any account. It reads the server's current export table (`/var/lib/nfs/etab`) without running `exportfs`, needs no root, and ignores Kerberos-only exports and stopped servers.

**Wider checks**
- CTR-001 covers Incus and LXD containers: privileged ones (`security.privileged`), host directories they can write (in unprivileged containers only shifted ones, `shift=true`, since root there is not the host's root), raw disks, and the Incus or LXD socket passed in. Configuration comes from each running container's `backup.yaml`, without the `incus` or `lxc` commands; `environment.*` values stay on the host.
- FS-003 and FS-004 read ACLs (with `getfacl`, where the `acl` package is installed): an account an ACL entry lets change a file root runs, or read a private key, is reported ("bob through an ACL on /opt/tool", "can be read by bob through an ACL"). Access is decided as the kernel does it, so with an ACL the owning group's rights come from its `group::` entry within the mask rather than the mode's group bits, and an account's own entry overrides what its groups allow; both used to be reported wrongly.

**Development**
- CI's script tests install the `acl` package, so the ACL tests run against a real `getfacl` under busybox and gawk.

**Upgrading**
- Nothing to change: the new checks run on the next scan. FS-005, the ACLs and Incus/LXD need root or passwordless sudo on the host, like the other checks that read other accounts' files; NET-003 does not.
- ACLs are read where `getfacl` is installed (the `acl` package, which is also what sets them).
- On hosts with ACLs, FS-003 findings can change: accounts that only seemed able to write through a masked group drop out, and accounts an ACL names appear.

## v0.3.0 — 2026-10-22

How long things have been wrong, and exceptions that do not last forever: every finding now says since when it has been open, in the dashboard, the reports and the metrics, and allowlist rules can end. Private keys outside `~/.ssh` are found too.

**How long findings have been open**
- How long each finding has been open ("open since 2026-09-03 (49 days)"), and which are new in the newest scan: on nobet-web's host and check pages, and in the HTML and PDF reports (`nobet scan -html/-pdf`, `nobet report`, the dashboard's downloads). A scan that skipped the check or failed does not end the count; counts and lists that change ("5 pending updates" instead of 3) do not either. A finding already in the oldest kept scan says "or earlier".
- Metrics (`-metrics`): `nobet_host_new_findings` (by severity, first reported in the host's newest scan) and `nobet_host_oldest_finding_opened_timestamp_seconds` (when the oldest open finding of a severity was first reported), for alerts like "a high finding open for more than a week".

**Allowlist**
- Rules can end: `until=YYYY-MM-DD` on a rule covers findings through that day and none after it, so an accepted risk comes back for review. Scans note rules that have ended or end within two weeks, and JSON output, the dashboard and the reports show the date with each allowlisted finding.

**Checks**
- FS-004 also finds private keys outside `~/.ssh` that ssh configurations name (`IdentityFile` in `/etc/ssh/ssh_config`, `ssh_config.d` and each account's `~/.ssh/config`), such as a backup job's key, and keys in the `.ssh` directories of applications under `/opt` and `/srv`.

**Development**
- CI runs the collector script tests under busybox (Alpine) and gawk (AlmaLinux) too, not only Ubuntu's mawk.

**Upgrading**
- Nothing to change: the dates come from the scan history you already have, from the next scan or dashboard start on.
- To make an existing exception end, add `until=YYYY-MM-DD` to its allowlist rule.

## v0.2.0 — 2026-10-21

Access that outlives its reason, and gaps nobody looks at: SSH keys nobody uses, private keys others can read, containers that are root on their host, published ports the firewall never sees, and login records that run out too soon. Plus reports from saved scans and a view per check for the team.

**New checks**
- ACC-006: authorized SSH keys that have not logged in for 90 days, from sshd's "Accepted publickey" messages in the journal and the syslog files (rotated and gzipped ones too); Medium when the key reaches an account that can become root. Only journal entries from root's sshd are trusted, so no local account can make a key look used there. When the logs do not reach back 90 days, the check says how far they go instead of guessing.
- ACC-007: passwords stored as DES or MD5 hashes (Medium for accounts that can become root). The shadow collector now names each set password's algorithm; the hash still never leaves the host.
- LOG-001: login records not kept for 90 days. Medium when sshd logs no logins, nothing keeps its messages, or only a journal in memory does; Low when they go back less than 90 days on a system older than that (judged by the root file system, `/etc/machine-id` and the basesystem package, so new servers and fresh cloud VMs are left alone).
- FS-004: private keys other accounts can read (accounts' SSH keys, sshd's host keys, TLS keys), following the permissions of every directory above them. Critical when every account can read a key that logs in to a root-capable account on the host. Key material never leaves the host.
- CTR-001: running Docker and podman containers that can take over the host: privileged, a control socket mounted (Docker, podman, containerd, CRI-O, systemd, D-Bus; read-only or through `/run` or `/` too, if the socket exists), host paths root runs mounted writable, escape capabilities, raw disks (High); the host's PID namespace or its password hashes and SSH keys readable (Medium); no seccomp or AppArmor (Low). The containers' environment never leaves the host.
- Ports published by containers count in NET-001 (which names the container, and also sees them with Docker's `userland-proxy` off), and NET-002 reports an active firewall that Docker's published ports go around: ufw, firewalld and INPUT rules never see them, unless `DOCKER-USER` filters them. Checked with real traffic: with ufw denying everything but SSH, a published port still answered.

**Root access map**
- Shows when each key last logged in as each account (text, TUI, HTML, PDF and the dashboard).
- Marks keys whose private half other accounts can read somewhere, with the host and path (FS-004): they get every route to root the key has, on every host.

**Reports, history and dashboard**
- `nobet report -pdf FILE` (and/or `-html FILE`): the reports from the saved history, without scanning, from each host's newest successful scan; `-host` narrows it. For a weekly report from cron.
- `nobet diff -since 7d` (`2w`, `36h`): what changed since each host's newest scan from before then, rather than since the previous scan.
- nobet-web: "Findings by check" on the fleet page, and a page per check (`/check/SSH-001`) with every host it fires on, where it is allowlisted and why, and where it could not run; check IDs on host pages link to it.

**Fixes**
- FS-003 no longer reports masked systemd services: their unit file is a link to /dev/null, which anyone can write to, but systemd never starts them.
- Local scans run each command without a controlling terminal, in a process group of its own: nothing can stop to prompt on the terminal nobet was started from, and a timeout now also stops what the command started.
- Binaries built with `go install …@v0.2.0` report their version instead of `dev`.
- The PDF report's subtitle wraps instead of running off the page.

**Releases**
- The release workflow builds the tag it was started for even when two tags share a commit (v0.1.0-rc1 and v0.1.0 did), and can rebuild an existing tag's release by hand (`gh workflow run release -f tag=vX.Y.Z`). Such runs are signed as `release.yml@refs/heads/master`; the verify commands in the README accept both. A run for a tag that is already released stops at the start instead of failing after the build.

**Upgrading**
- Nothing to change: the new checks run on the next scan. Allowlist what you have reviewed, by container name (`CTR-001 * traefik`) or key fingerprint (`ACC-006 * SHA256:...`).
- ACC-006, ACC-007, LOG-001, FS-004 and CTR-001 need root or passwordless sudo on the host, like the other checks that read other accounts' files.
- 100 saved scans of 50 hosts take about 80 MB (75 MB before); the container list is not stored.

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
