# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately. Don’t open a public issue. That can expose the problem before there is a fix.

The best way to report one is through GitHub’s private vulnerability reporting. Go to the [Security tab](https://github.com/ioni-dev/mati/security/advisories), then click “Report a vulnerability.” GitHub will create a private advisory that only you and the maintainers can see.

When you report an issue, please include the useful basics:

- what the issue is, and what impact it could have
- how to reproduce it, ideally with a minimal example
- the affected version, from `mati --version`
- your platform

You should hear back within a few days. Once a fix is ready, we’ll coordinate disclosure with you and credit you in the release notes, unless you would rather stay anonymous.

## Supported versions

mati is still pre-1.0. Security fixes are made against the latest release on `main` and the most recent crates.io version. Older releases are not maintained.

## Design notes relevant to security review

mati is a local-first tool. A few security assumptions are worth knowing before you start testing.

- **No network calls in the enforcement path.** Hook DENY/ALLOW decisions and the enforcement event log are computed entirely on the local machine. The open-source binary should never phone home in that path. If it does, please report it as a bug.

- **The daemon is local-only.** It listens on a Unix domain socket under `~/.mati/<slug>/`. Connections are accepted only from the same UID, with peer credentials checked. It is not a network service.

- **Hooks fail open.** If mati cannot be reached, a hook allows the operation instead of blocking it. That is intentional: availability takes priority over enforcement here. Please report any input that makes a hook hang, crash, or block the host agent past its deadline.

Out of scope: the separate commercial `mati-cloud` product, which has its own reporting channel, and issues that require an already-compromised local account. same-UID access is the trust boundary.
