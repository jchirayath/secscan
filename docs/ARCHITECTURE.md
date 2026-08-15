# Architecture

Why secscan is built the way it is. Source comments point here by section name
rather than number, so references do not drift as this document grows.

---

## Constraints

Four constraints shape everything else. They are enforced by `ci/guards.sh`, not
by convention — a rule nothing checks is decoration.

### Zero dependencies

`go.mod` has an empty `require` block and a guard fails the build if anything is
added. A security tool that pulls 200 transitive modules has a supply chain
larger than most of what it scans.

The cost is real and accepted: no fancy TUI, no YAML config, hand-rolled JSON
handling in places. In exchange the binary is auditable in an afternoon and the
only CVE surface is Go's standard library.

### No database

State is `state.json` + `history.jsonl` + an in-memory index rebuilt at boot.
Writes are atomic (temp file + rename), so an interrupted write cannot leave a
half-state that later reads as real.

Postgres would mean an operator installs a database to scan one host. The
tradeoff is that this design suits tens of hosts, not thousands.

### No UI build step

One embedded HTML file, one CSS file, one vanilla-JS file, served via `go:embed`.
No npm, no bundler, no `node_modules`. The dashboard is readable in a browser's
view-source.

### No agent on the target

Scanning happens over SSH using the system `ssh` binary, or locally. Nothing is
installed on the machine being scanned.

---

## Transport

`internal/core/exec` shells out to the system `ssh` rather than vendoring a
crypto stack. That inherits the operator's `known_hosts`, agent, jump hosts and
per-host config — settings they have already audited — and keeps dependencies at
zero.

Host-key checking is **on** by default; disabling it is per-target, explicit,
and logged loudly at WARN.

Every remote command is assembled by quoting each argv element individually,
never by interpolating a format string, so a hostile target name or path cannot
inject. A guard rejects string interpolation in command construction.

Connections use SSH `ControlMaster` multiplexing. Without it a scan's dozens of
commands each pay a full handshake — measured at ~26s for one host, versus a few
seconds shared.

### Privilege

The transport prepends `sudo -n` only for an explicit, short allow-list of reads
that genuinely need root. A scanner that runs everything as root is its own risk.

Remediation declares its privilege separately and explicitly — see
[Remediation](#remediation).

---

## Collectors and engines

**Collectors** (`internal/core/collect`) are native Go checks and the primary
source of findings: listening sockets, identity and sudo policy, file and
directory hygiene, privilege-escalation paths, service configuration, DNS
hygiene, reachability, compensating controls.

**Engines** (`internal/core/engine`) wrap external tools — Trivy, gitleaks,
osv-scanner, nuclei, testssl.sh — and are enrichment, not the foundation.
secscan produces a useful assessment with none of them installed.

Each engine adapter is a claim about another program's output format. The only
way to keep that claim honest is a golden fixture captured from a real run, which
is why `testdata/` exists — an adapter written against documentation alone has
been wrong here more than once.

---

## Findings

`internal/core/finding` is the one shape everything produces and consumes. Field
names mirror common finding/vulnerability table layouts so an exporter to another
system stays mechanical.

A finding carries: identity and fingerprint, severity, category, the asset and
component, evidence (the literal command and its output), references,
remediation, exposure state, validation verdict, compensating controls, and the
risk factors that produced its score.

**Evidence is mandatory.** A finding you cannot trace to a command and its output
is an assertion, and assertions do not survive contact with an operator who
disagrees.

---

## Risk

`internal/core/risk` holds exactly one `Score()` implementation, and a guard
asserts no other package multiplies severity by anything.

```
inherent = base(severity) × (1 + 2·EPSS) × KEV(2.0) × exposed(1.5) × critical(1.3)
residual = inherent × mitigation_factor
```

Two divergent scorers is a bug that ships easily: the dashboard sorts on one,
remediation eligibility decides on the other, and "why is this at the top?" gets
two answers, neither wrong.

Every applied multiplier is returned alongside the score and rendered in the UI.

See [INTERPRETING-RESULTS.md](INTERPRETING-RESULTS.md) for what the numbers mean
and where the score's known limitations are.

---

## Exposure verification

A wide-bound socket is only *potentially* exposed. secscan probes each from
outside the host: a TCP connect, then a vhost-aware HTTP probe that follows the
`Host` header, because a reverse proxy serves a different site per name and
probing the IP alone reaches only the default one.

Results aggregate worst-case across the names a host serves. A port is
"protected" only if every name on it is.

The probe's limitation is stated in the output rather than hidden: it runs from
wherever secscan runs, so "blocked upstream" means blocked *from here*.

---

## Compensating controls

A control reduces risk; it never clears a finding. Three rules:

1. It must be **verified active** — installed-but-inactive mitigates nothing.
2. It must be **scoped to the affected service**.
3. The reduction is **floored**, and the inherent figure stays visible as what
   the risk returns to if the control fails.

Every control declares what it does **not** cover, and that limitation is shown
every time the control is credited. A control presented without its limits
becomes an excuse not to fix the underlying problem.

---

## Validation

Where a safe test exists, secscan runs it instead of inferring. Rules for every
validator:

- **Non-destructive** — unique temp names, removed afterwards; nothing persisted,
  restarted, or denied service.
- **No credentials** — it may ask a service which auth methods it offers; it
  never tries one.
- **Unprivileged** — the question is "can an ordinary local user do this?", so a
  test that quietly ran under sudo would answer a different question and get the
  verdict wrong in both directions.
- **Honest on failure** — a test that cannot run yields `unverified`, never
  `refuted`. Absence of proof is not proof of absence.

---

## Provenance and honest degradation

Every API response carries `live | cached | demo | partial | unavailable`, and
the dashboard cannot render stale or demo data without a banner.

Every check that did not run is reported with its reason. **This is the single
most important property in the codebase.** "Found nothing" and "never looked" are
different answers, and a tool that renders them identically is worse than no tool,
because it converts an unknown into a false all-clear.

---

## Authentication

Three modes:

| Mode | Use | Enforcement |
|---|---|---|
| `entra` | Production | OIDC authorization-code + PKCE, HMAC-signed session cookie |
| `proxy` | Behind an authenticating reverse proxy | Identity headers accepted **only** from configured trusted peers |
| `local` | Local inspection | **Refuses to start** on a non-loopback bind |

The refusals are deliberate. `local` on a routable address would put an
unauthenticated map of your estate's weaknesses on the network; `proxy` without a
trusted-peer list lets anyone who can reach the port assert any identity. Both
are authentication bypasses, so both fail closed at boot rather than warn.

---

## Authorization

Every API route declares a capability, and `ci/guards.sh` fails the build on any
route that does not. The classic failure is hundreds of routes against a handful
of authorization call sites — nobody decides that, it accumulates because nothing
fails the build.

Roles are small and fixed; capabilities are the unit of enforcement.
`remediate.apply` is granted to admin only.

---

## Audit

Append-only, and every entry carries the authenticated user **and** the role they
acted under as two separate fields. Roles are shared — several people hold
`operator` — so a record with only the role cannot answer "which of them?", and
one with only the user cannot answer "under what privilege?".

Mutating actions are audited **before and after**, so an action that hangs or
crashes the process still leaves a record of what was started and by whom.

---

## Configuration

`internal/config` is the only place in the binary that reads the environment; a
guard fails the build on `os.Getenv` anywhere else.

Every key is declared once with type, default, required-ness, secret-ness and
description. The process refuses to start if a required key is missing.
`secscan config -example` generates the `.env` template from that registry, so
the template cannot drift from what the binary reads.

---

## Outbound HTTP

`internal/httpx` is the only outbound HTTP client: one client, mandatory timeout,
TLS 1.2 floor. A guard rejects `http.Client{}` literals and `InsecureSkipVerify`
anywhere else, with narrowly-scoped, commented exceptions for the exposure probe
(which must suppress redirects and must tolerate a bad certificate — reporting
one is its job).

---

## Error codes

A closed registry of constants. An open-ended vocabulary drifts into synonyms
(`persist_failed` / `store_error` / `store_failed`) that clients cannot switch
on. A guard rejects string literals in the error-code position.

---

## Time

All time comes from `internal/clock`; a guard rejects `time.Now()` elsewhere, so
tests can control it. Snapshot IDs are timestamps, and a scanner whose output
depends on an uninjectable clock cannot be tested deterministically.

---

## Remediation

The only part of secscan that changes a scanned host on purpose.

**The colour rates the change, not the finding.** Severity says how bad the
problem is; change-risk says how bad it would be if the fix went wrong. A
CRITICAL finding can have a trivial fix; a LOW one can have a fix that removes
your access to the machine.

Invariants are enforced in code rather than trusted to the author of a catalogue
entry: anything touching the access path becomes red, anything needing a restart
cannot be green, and anything without a verification step cannot be green — a fix
that cannot be proven to have worked is not one to apply unattended.

**Only green executes**, and the refusal lives inside `Apply()` so no future
caller can route around it by forgetting to check.

Fixes come from a hand-written allow-list. Nothing is generated from a finding's
own remediation text: generating shell from a finding and running it as root is
how a scanner becomes the incident.

Order: `canary → backup → apply → canary → verify → rollback-on-failure`. The
second canary catches a fix that cost us the host while an operator is still
watching. Verification tests the condition on the host, mirroring the collector's
own predicate — never the exit code of the fix.

Two rules learned by getting them wrong first:

- **Verification must be at least as wide as the check it answers.** A fix that
  repairs four paths but verifies two turns an open finding into a false
  all-clear.
- **Fixes tighten with relative modes, never absolute ones.** `chmod 640
  /etc/shadow` *loosens* a host already at 600; `chmod g-wx,o-rwx` cannot.

Privilege applies to apply and rollback only. Backup and verify always run
unprivileged, because verification is stronger from the same vantage point the
collector had.

---

## Guards

`ci/guards.sh` enforces the above with shrink-only allow-lists. Exceptions
require an inline `secscan:allow-<guard>` marker with a stated reason, so every
exception is visible in the diff that introduces it.

Guards cover: zero dependencies, single risk implementation, route-capability
coverage, `os.Getenv` containment, HTTP client containment, `InsecureSkipVerify`,
error-code literals, `time.Now()` containment, CSS hex literals outside `:root`,
command interpolation, committed scan output, `.env.example` currency, secret
scanning, and **disclosure of real infrastructure or private-codebase details**.

That last one exists because both classes reached this repository at least once
and had to be scrubbed.
