<h1 align="center">secscan</h1>

<p align="center"><em>Every weakness on your servers, ranked by whether it can actually be reached.</em></p>

A compact security posture scanner. **One ~11 MB static binary, zero
dependencies, no database, no build step.** Drop it on a server, gate it with
Entra ID, and get an interactive dashboard of every issue found — organised by
category, drillable to raw evidence, with a remediation plan that tells you
which fix clears the most risk.

```
secscan scan web01          # scan a host over SSH
secscan serve               # dashboard on :8788
```

## Why it ranks differently

Most scanners hand you a wall of CVSS numbers. A critical CVE on a service
bound to `127.0.0.1` behind a firewall is not the same risk as the same CVE on a
port the world can reach — but raw CVSS scores them identically.

secscan maps every listening socket to its owning process, user and bind
address, then feeds that into one risk score:

```
risk = base × (1 + 2·EPSS) × KEV(2.0) × exposed(1.5) × critical_asset(1.3)
```

Every multiplier is shown in the UI, so *"why is this at the top?"* always has
an answer.

## Exposure is verified, not assumed

A socket on `0.0.0.0` is only *potentially* exposed. secscan probes each
wide-bound port from outside the host and reclassifies it:

| Verdict | What it means | Effect |
|---|---|---|
| **blocked upstream** | TCP connect fails — a firewall or cloud security group drops it | dropped to `info`, exposure cleared |
| **behind authentication** | reachable, but anonymous requests get 401/403 or bounce to an identity provider | severity down one step |
| **openly reachable** | answers anonymously | kept, with evidence |

Reverse proxies route by `Host`, so probing the IP only ever reaches the default
site. Declare the other names with `-vhosts` and each is probed separately —
that is how a vhost sitting behind Entra is recognised as protected instead of
scored as an open port. The aggregate is worst-case: **a port is only as
protected as its weakest site.**

```
secscan targets add web01 scan@web01.example.net \
  -key ~/.ssh/secscan -sudo -critical \
  -vhosts ssh.example.net,uptime.example.net
```

## Turning checks on and off

Every collector and engine appears in the **Checks** view with a plain-English
description of what you lose by disabling it. A disabled check is *reported as
disabled* in Coverage — never silently omitted, because a check that vanishes
looks exactly like a check that passed.

Optional engines can be installed from the UI (`admin` only). The exact commands
are shown before you confirm, installation is audited before and after, and
success is verified by re-probing for the binary rather than trusting an exit
code. There is no `curl | sh` anywhere: a security tool that installs itself by
piping the internet into a shell is arguing against its own findings.

## What it checks

Ten categories, all from **native collectors that need no external tools**:

| | |
|---|---|
| **Patches** | pending security updates, reboot-required, auto-update posture |
| **Network** | listening sockets with owning process, wide binds, management-port exposure |
| **Identity** | empty passwords, UID-0 accounts, `NOPASSWD` sudo, password policy, SSH daemon config |
| **Containers** | privileged, `docker.sock` mounted, root user, host netns/PID, unpinned tags, no limits |
| **Hardening** | sysctl posture, world-writable files, firewall state |
| **Ops** | time sync, audit logging |
| **Deps · Web · Secrets · Services** | via optional engines |

Optional engines — **Trivy**, **gitleaks**, **osv-scanner** — are auto-detected
and add depth. Their absence never leaves a silent gap: the scan reports exactly
what did not run and why.

## Honesty by construction

A security tool that reports nothing when it is broken is worse than no tool.

- Every collector that cannot run says so, with the reason.
- If SSH auth fails, the scan **fails loudly** — it does not report "no
  vulnerabilities found".
- Every response carries `provenance: live | cached | demo | partial |
  unavailable`. Demo data can never render without a banner.
- Every finding carries the exact command and its raw output as evidence.

## Authentication

Three modes (`--auth`):

- **`entra`** — the binary runs the OIDC code+PKCE flow against a single Entra
  tenant and issues an HMAC-signed session cookie. No OIDC library.
- **`proxy`** — behind App Service Easy Auth or Entra App Proxy; trusts
  `X-MS-CLIENT-PRINCIPAL-*`, **but only from a declared trusted peer** —
  header trust without a peer check is a full auth bypass.
- **`local`** — no auth, **loopback bind only**. Combining it with a public bind
  is a startup error, not a warning.

Authorization is a shared guard on every route, default deny, with five roles
(`viewer · auditor · security_analyst · operator · admin`). A route with no
declared capability fails CI. Every denial is audited with the caller **and**
the role they acted under.

## Install

```bash
go build -o secscan ./cmd/secscan

secscan targets add web01 scan@web01.example.net -key ~/.ssh/id_ed25519 -sudo -critical
secscan scan web01
secscan serve -bind 127.0.0.1:8788 -auth local
```

The scan account needs no root: give it a narrow sudoers allow-list for the
handful of privileged reads (`/etc/shadow`, `sshd_config`, `ss -tulpnH`,
`docker inspect`). A scanner that is root-equivalent is its own worst finding.

Full instructions, including the sudoers grant, optional engines and Entra ID
setup: **[docs/INSTALL.md](docs/INSTALL.md)**.

**Scheduled scans.** Set `SECSCAN_SCAN_INTERVAL=24h` and `secscan serve` scans
every target on that cadence (first pass two minutes after start), recording
each run in the audit log as `scheduler`. Schedule it this way, not with cron
calling `secscan scan`: the server keeps state in memory, so a separate scan
process writes results the dashboard does not show until a restart, and the
dashboard's next save can overwrite them.

**False positives and accepted risks.** On a finding, *Mark false positive…*
or *Accept this risk…* — a reason and an expiry (1–365 days) are mandatory
either way, and the two kinds stay distinct in the report: one says the scanner
was wrong, the other that a real problem is tolerated. *Applies to* can widen a
decision from the one finding to a **rule** (same rule ID, same component, same
location, or everything under a folder), which also covers future scans — the
only way a false positive survives the next package version bump. Rules are
listed, counted and revoked under *Suppressions*; revoking reopens what they
hid. Rules naming only an engine or a bare `*` are refused. From the command
line, with `serve` stopped: `secscan rules add -kind false_positive -reason
"testssl sample keys" -days 365 -engine gitleaks -location '/opt/testssl.sh/*'`.

## Architecture

Zero external Go dependencies, enforced by CI. Everything is stdlib: HTTP, TLS,
JSON, HMAC, process execution. SSH shells out to the system `ssh` (with
connection multiplexing) rather than vendoring a crypto stack — which also
inherits your existing `known_hosts`, agent and jump-host config.

State is a JSON document plus an append-only JSONL history. No database.

```
cmd/secscan            CLI
internal/config        the ONLY place that reads the environment
internal/core/collect  native collectors
internal/core/engine   optional adapters (trivy, gitleaks, osv-scanner, nuclei, testssl)
internal/core/risk     THE risk score — exactly one implementation
internal/remediate     the only component that changes a scanned host
internal/web           API + embedded dashboard (one HTML/CSS/JS file each)
ci/guards.sh           architecture guards, shrink-only allow-lists
```

`./ci/guards.sh` fails the build on: a new dependency, `os.Getenv` outside
config, an `http.Client` literal, `InsecureSkipVerify`, a raw error-code string,
`time.Now()` outside the clock, a second risk score, an unguarded route, an
audit entry missing its role, a hex colour, an inline style, a bare `fetch()`,
an unescaped DOM interpolation, committed scan output, or a real hostname.

## Documentation

| | |
|---|---|
| **[INSTALL.md](docs/INSTALL.md)** | Build, scanning account, sudoers, optional engines, Entra ID |
| **[USAGE.md](docs/USAGE.md)** | Every command, the dashboard, reports, trend, remediation |
| **[INTERPRETING-RESULTS.md](docs/INTERPRETING-RESULTS.md)** | What every number means — and what it does not |
| **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** | Why it is built this way |
| **[TOOL-LANDSCAPE.md](docs/TOOL-LANDSCAPE.md)** | What else exists, licences, and why hybrid |
| **[SECURITY.md](SECURITY.md)** | Reporting a vulnerability; secscan's own threat model |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | The rules a change has to satisfy |

## Authorized use only

Scan only systems you own or have explicit written authorization to test. Every
intrusive module is off by default. Online password brute-forcing is not a
feature and will not be added.

## License

GPL-3.0 — see [LICENSE](LICENSE).

Nmap is never vendored: its NPSL licence is GPL-incompatible.
