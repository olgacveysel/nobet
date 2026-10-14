# nöbet (nobet): notes for Claude

Agentless Linux security auditor in Go. Scans the local machine or remote hosts over SSH, read-only. Target users: small teams (up to ~50 servers). Maintainer: Veysel (Linux/infra engineer). License: Apache-2.0.

## First thing to do in a new session

Run the checks before and after changing anything:

```bash
go mod tidy && go vet ./... && go test ./... && go build ./cmd/nobet ./cmd/nobet-web
```

On Windows without a Go toolchain, the WSL distro has one in `~/.local/goroot/bin`. Windows-only code (the ssh-agent named pipe) is tested by cross-compiling test binaries (`GOOS=windows go test -c`) and running them on Windows; CI also runs a windows-latest job.

## Layout

```
cmd/nobet/          CLI: main.go (dispatch, banner), targets.go (shared host flags), scan.go, rootmap.go, diff.go
cmd/nobet-web/      read-only dashboard binary (flags, server, graceful shutdown)
internal/runner/    Runner interface and Result only (no dependencies)
internal/transport/ Local (/bin/sh) and SSH runners (agent incl. Windows pipe, keys, strict known_hosts, ProxyJump chains)
internal/fleet/     Local/Remote scans: the only package that connects to hosts; CLI only
internal/sshconf/   ~/.ssh/config (or -F file) resolution via kevinburke/ssh_config
internal/inventory/ [user@]host[:port] parsing; Port 0 / User "" mean "not given"
internal/collect/   Facts + collector shell scripts (scripts.go) + parsers
internal/checks/    Check{ID, Title, Run(facts) (findings, skip)}; registry in check.go All()
internal/scan/      HostResult (Facts kept, json:"-") and Evaluate(facts -> findings)
internal/allow/     allowlist (check-id host-glob [match] # reason)
internal/store/     scan history in ~/.local/share/nobet/scans or $NOBET_DATA_DIR/scans (0700/0600; 0640 in a group-readable dir; keep 100)
internal/drift/     changes between two snapshots of a host
internal/rootmap/   fleet-wide "who can become root where", grouped by SSH key
internal/report/    text, JSON, HTML (embedded template + logo in assets/)
internal/tui/       Bubble Tea UI; `r` toggles root access view
internal/web/       nobet-web: history index, pages (embedded templates/ and static/)
contrib/systemd/    nobet-scan.service/.timer and nobet-web.service (hardened)
contrib/docker/     nobet-scan-loop: the scanner image's entrypoint
Dockerfile          one build, two targets: scanner (alpine) and web (distroless), uid 65532
compose.yaml        scanner (holds the key, writes the volume) + web (volume read-only, 127.0.0.1 only)
internal/brand/     half-block terminal logo (owl on the ö)
docs/logo/          SVG logos, favicon
```

## Conventions (keep these)

- **Read-only on targets.** Collector scripts only read state. Never refresh package metadata, never install or change anything.
- **Scripts are shipped base64-encoded** (`script()` in collect.go) so quoting can't break them; `asRoot` runs them via `sudo -n sh` when passwordless sudo exists.
- **nil vs empty matters.** A nil Facts field means "could not collect" and the check must return a skip reason; an empty slice means "collected, nothing there". Never let missing data look like a pass.
- **Scripts must not hide unreadable data.** A script that ends in `true` succeeds even when nothing was readable; gate it on privilege or print a marker (see `nocache=` for dnf5). `Facts.SSHD` is nil when unreadable and an empty map when sshd is not installed (`NoSSHD`).
- **sshd views.** `Facts.SSHD` is the config for an arbitrary account from TEST-NET-1; `SSHDMatch` holds per-account/per-address differences. Read sshd settings through `SSHDViews`/`LoginAllowed`, not `f.SSHD` directly, so Match blocks count.
- **Never collect secrets.** The shadow collector prints only set/empty/locked; a test asserts no `$` reaches the output. Anything put into a generated script must be validated first (see `safeUser`).
- **Privilege gating.** Data that is only complete as root (other users' keys, sudo rights, firewall, SUID/world-writable) is skipped entirely without privilege rather than collected partially.
- **Drift compares like with like.** Root/key changes only when both scans were privileged.
- **Every parser has a test** with realistic sample output. Add one for every new collector. Where the logic is in awk, run the real script in the test (see `TestShadowScript`, `TestZypperScript`).
- **Verify against real systems.** Distro behavior is easy to guess wrong (dnf5/apk/zypper exit 0 with no cache; CentOS 7's root password field is `locked`). Throwaway containers (`docker run --rm -v nobet:/nobet:ro <image>`) running the static binary are the quick check.
- **Severities:** Critical = direct path to root for anyone; High = serious exposure; Medium = should fix; Low = hardening; Info = context.
- **Output modes:** TUI only on an interactive terminal; `-plain`/`-json`/pipes print plain output. JSON on stdout must stay valid (notes go to stderr).
- **Exit codes:** 0 ok, 1 findings ≥ `-fail-on` (or changes for `diff`), 2 usage, 3 unreachable hosts.
- **Release with a current Go.** `go.mod` only sets the minimum (1.26); CI and the release workflow use the latest stable Go, and CI runs govulncheck. Run `govulncheck ./...` before tagging; x/crypto/ssh is on the attack surface.
- **Stream the history.** Read scans with `store.Walk` or `store.Recent`, one file at a time; never load the whole history (100 scans of 50 hosts is ~75 MB on disk and ~250 MB in memory). Measured at that size: diff 0.4 s / 31 MB, dashboard 24 MB.
- **Separate binaries stay separate.** `cmd/nobet/deps_test.go` fails if the CLI links `net/http` or `internal/web`; `cmd/nobet-web/deps_test.go` fails if the dashboard links `transport`, `fleet`, ssh-agent, known_hosts or `os/exec`. Keep result types in `scan`/`store` free of transport imports.
- **Brand:** navy #0B1426, tile #16223B, cream #EDE9DF, amber #F2A93B (dark-on-light amber #D9890F). Lowercase "nöbet" in UI; binary/module names stay ASCII `nobet`.

## nobet-web design decisions (keep these)

Decided by the maintainer on 2026-10-14:

- **Separate binary in this repo**, not a separate repo: Go forbids importing `internal/` from another module, and a public `pkg/` API is not worth versioning yet. Own packages (`nobet` and `nobet-web` deb/rpm/apk), shared version and changelog. Revisit only if the dashboard gets its own contributors or release rhythm.
- **Read-only over scan history.** It never scans and never holds SSH credentials. Scans come from `nobet scan` under a service account (systemd timer) writing to a shared history (`/var/lib/nobet/scans`). If on-demand scans are ever needed, the web process only queues a request and a separate worker running the CLI under the service account does the scan; the web process still never touches a key.
- **For teams, with access control from day one.** v1: localhost only by default, behind the team's authenticating reverse proxy; no built-in login code. v2: built-in OIDC login with a read-only role and an audit log of who viewed what.
- No JavaScript, strict CSP (no inline styles either), pages `no-store`, GET/HEAD only.

## Release

- Module `github.com/olgacveysel/nobet`; `.goreleaser.yaml` has homepage and maintainer (Veysel <olgacveysel@gmail.com>). `goreleaser check` and a snapshot release pass.
- Not yet a git repository. To release: create the GitHub repo, push, then `git tag v0.1.0 && git push --tags`; the release workflow does the rest. CHANGELOG.md has the notes.

## Roadmap (next)

- Beta: create the GitHub repo, get CI green, tag v0.1.0-beta.1 (goreleaser marks it a pre-release); test on real servers (firewalls, /boot kernels and real package states never appear in the container lab)
- Publish container images to GHCR from the release workflow (compose builds locally for now)
- Sign release artifacts (cosign) and publish an SBOM
- nobet-web v2: OIDC login, read-only role, audit log of who viewed what (see design decisions)
