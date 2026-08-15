# Security policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/jchirayath/secscan/security/advisories/new).
Please do not open a public issue for an unfixed vulnerability.

Include what you did, what happened, what you expected, and the version
(`secscan version`). A proof of concept helps; a working exploit is not required.

Expect an acknowledgement within a few days. This is a small project, not a
funded programme — there is no bounty, and fix timelines depend on severity and
available time. Credit is given unless you ask otherwise.

---

## secscan's own threat model

A tool that finds weaknesses becomes a high-value target, because its output is
a map of exactly where to attack. That shapes the design.

### The dashboard is the crown jewel

Scan results describe every weakness on every scanned host. Anyone who reaches
the dashboard gets that map. Accordingly:

- `local` auth mode **refuses to start** on a non-loopback bind. It is not a
  warning you can click past.
- `proxy` mode **refuses to start** without `SECSCAN_TRUSTED_PROXIES`. Accepting
  identity headers from any peer is an authentication bypass.
- Session secrets under 32 bytes are rejected at boot.
- Every API route declares a capability; CI fails on any route that does not.

### Scan output is sensitive data

`state.json`, `history.jsonl` and everything under `snapshots/` are a complete
inventory of your hosts' weaknesses. Snapshots are written `0700`/`0600`.
**Never commit them** — the shipped `.gitignore` and a CI guard both block it.
Treat a leaked snapshot as more serious than a leaked credential.

### The scanner is not root

secscan is built to run as an unprivileged account and degrade honestly. A
scanner that is root-equivalent on every host in the estate is a single
compromise away from being the worst thing in it.

Where privilege is genuinely needed, the recommended sudoers grant is an
exact-match allow-list. **Never** grant `NOPASSWD: ALL`, and never wildcard a
shell: `/usr/bin/sh -c *` is not a narrower grant than `ALL`, it is the same
grant spelled longer.

### Remediation cannot be tricked into arbitrary execution

The one component that changes hosts runs only hand-written playbooks from a
compiled-in allow-list. **Nothing is generated from scanner output.** If a
finding's text could become a command, then anything able to influence a package
name, a file path or a CVE description could execute code as root. It cannot.

Only fixes rated green run at all, and the refusal for amber and red lives inside
the executor, not in its callers.

### Injection surfaces we treat as hostile

- **Findings contain attacker-influenced strings** — file paths, process names,
  package names, CVE descriptions. Every value reaching the DOM is escaped, and
  a CI guard rejects unescaped interpolation. A strict CSP is the backstop, not
  the plan.
- **Reference URLs come from engine output.** Only `http`/`https` are rendered as
  links, so a `javascript:` URL cannot execute on click.
- **Remote commands** are built by quoting each argv element individually, never
  by interpolating a format string.

### What secscan deliberately will not do

- **No online password guessing**, ever. It may ask a service which auth methods
  it offers; it never attempts one.
- **No destructive validation.** Tests are non-destructive, use unique temp names,
  and clean up.
- **No exploitation.** Validation proves a condition exists; it does not weaponise
  it.
- **No unattended amber or red fixes**, regardless of how the caller asks.

### Known limitations

- Exposure probes run from wherever secscan runs. **"Blocked upstream" means
  blocked from here** — a scanner inside the same network segment says nothing
  about the internet.
- Compensating controls are credited only when verified active and scoped to the
  service, but crediting is still a judgement. The inherent risk is always shown
  as what the number returns to if the control fails.
- `unverified` means no safe test existed or it could not run. It is never
  evidence of absence.
- Findings from external engines inherit those engines' false positives. Two
  systematic cases are handled explicitly (see
  [INTERPRETING-RESULTS.md](docs/INTERPRETING-RESULTS.md)); others will exist.

---

## Authorized use only

Scan only systems you own or have explicit written authorization to test. The
web engines send real traffic to live services. Every intrusive module is off by
default.
