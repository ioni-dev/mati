# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Do not open a public issue,
since that discloses the problem before a fix is available.

Use GitHub's private vulnerability reporting: open the
[Security tab](https://github.com/ioni-dev/mati/security/advisories) and click
"Report a vulnerability." That creates a private advisory visible only to you
and the maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal case if you can),
- the affected version (`mati --version`) and your platform.

Expect an initial response within a few days. When a fix is ready we will
coordinate disclosure and credit you in the release notes, unless you prefer to
stay anonymous.

## Supported versions

mati is pre-1.0. Security fixes target the latest release on `main` and the most
recent crates.io version. Older versions are not maintained.

## Design notes relevant to security review

mati is a local-first tool, and a few invariants are worth knowing before you
test:

- **No network calls in the enforcement path.** Hook DENY/ALLOW decisions and
  the enforcement event log are computed entirely on the local machine; the
  open-source binary never phones home. A network call in that path is itself a
  bug worth reporting.
- **The daemon is local-only.** It listens on a Unix domain socket under
  `~/.mati/<slug>/` and accepts connections only from the same UID (peer
  credentials are checked). It is not a network service.
- **Hooks fail open.** If mati is unreachable, a hook allows the operation
  rather than blocking it (availability over enforcement). Please report any
  input that makes a hook hang, crash, or block the host agent past its
  deadline.

Out of scope: the separate commercial mati-cloud product (report those through
its own channel), and issues that require an already-compromised local account,
since same-UID access is the trust boundary.
