# Security policy

nöbet runs with root (or passwordless sudo) on the servers it audits, and its
scan history describes weaknesses and which keys open which servers. Security
reports are taken seriously.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on
[github.com/olgacveysel/nobet](https://github.com/olgacveysel/nobet/security/advisories/new).
Do not open a public issue.

Include what you found, how to reproduce it, and the version (`nobet version`
or `nobet-web -version`). You should get a reply within a week. Fixes are
released as soon as they are ready and credited in the changelog unless you
prefer otherwise.

## Supported versions

During the 0.x series only the latest release receives security fixes.

## What is in scope

- Anything that lets a scanned host, a scan history file or a network
  attacker make `nobet` run commands it should not, change a scanned host,
  or leak credentials. nobet must stay read-only on targets.
- Anything that lets someone reach `nobet-web` data without going through the
  reverse proxy in front of it, or make `nobet-web` do anything but read the
  scan history.
- Findings that are silently wrong in a way that hides a real problem (a check
  that passes when it could not collect its data, for example).

Missing checks and false positives are welcome as normal issues.
