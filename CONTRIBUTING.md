# Contributing

## Before you start

```bash
go build ./...
go test ./...
./ci/guards.sh
```

All three must pass. `guards.sh` is not advisory — it is how this codebase stays
the way it is.

---

## The rules a change has to satisfy

These are not style preferences. Each one exists because violating it caused a
real bug here.

### 1. No new dependencies

`go.mod` has an empty `require` block and a guard enforces it. If you need
something, write it or do without. A security tool with a large supply chain is
its own worst finding.

### 2. A check that cannot run says so

Never return "found nothing" when the truth is "could not look". If a tool is
missing, a permission is denied, or a parse fails, the check reports as not-run
**with the reason**. Silently converting an unknown into a clean result is the
one failure mode treated as unforgivable here.

### 3. Findings carry evidence

Every finding needs the literal command and its output. A finding an operator
cannot verify is an assertion, and assertions lose arguments with the person who
owns the host.

### 4. Adapters need a golden fixture

An engine adapter is a claim about another program's output format. Capture real
output, **sanitise it** (see below), and commit it as a fixture. Adapters written
from documentation alone have been wrong here more than once — in one case
parsing nothing at all while reporting success.

### 5. Nothing is generated from scanner output and executed

Remediation runs only hand-written playbooks from the compiled-in catalogue. If
you are tempted to build a command from a finding's fields, don't: anything able
to influence a package name or file path would then execute code as root.

### 6. Adding a remediation playbook

You must write the **backup, the verification and the rollback** — not just the
change. Then:

- **Verification must be at least as wide as the check it answers.** A fix that
  repairs four paths but verifies two turns an open finding into a false
  all-clear. This is worse than no fix.
- **Tighten with relative modes, never absolute ones.** `chmod 640 /etc/shadow`
  loosens a host already at 600.
- **Green means it cannot cost you the host.** Anything touching networking, SSH,
  authentication or boot is red by definition, and the constructor enforces that
  rather than trusting your rating.
- Verify unprivileged where possible — it answers the same question the collector
  asked.

### 7. Every route declares a capability

CI fails on an unguarded `/api` route.

### 8. Escape everything that reaches the DOM

Findings contain attacker-influenced strings. Use `esc()` or text nodes. A guard
rejects unescaped interpolation.

### 9. Use the shared primitives

`internal/config` for environment, `internal/httpx` for outbound HTTP,
`internal/clock` for time, `internal/apierr` for error codes, `internal/audit`
for who-did-what. Guards fail the build on bypasses.

An exception needs an inline `secscan:allow-<guard>` marker **and** a comment
saying why, so it is visible in the diff that introduces it.

---

## Never commit

- **Scan output** — `state.json`, `history.jsonl`, `audit.jsonl`, `snapshots/`.
  A snapshot is a complete map of a host's weaknesses.
- **Real hostnames, IPs, or cloud resource identifiers.** Sanitise fixtures to
  `example.net` and the documentation-reserved ranges (RFC 5737). Replace
  *subdomain labels* too — swapping the domain but keeping `billing.`, `vpn.` and
  `backup.` still publishes an inventory of what you run.
- **Captured HTTP response bodies** you have not read in full. Fixtures exist to
  pin an output *shape*; a 60 KB embedded page body is incidental and is exactly
  where an internal service listing hides.
- **Details of private codebases** — a name plus "N routes against M capability
  checks" is a published characterisation of that system's authorization gap.

`ci/guards.sh` enforces this generically: fixtures and source may only reference
documentation domains (`example.net`, RFC 5737 addresses). It deliberately does
**not** contain a list of forbidden names — an earlier version did, which meant
the guard file itself published an inventory of the estate it was defending.

For site-specific names that do not look like domains (a host called `atlas`, an
internal codename), create `ci/disclosure-denylist.local` — one extended regex
per line. It is gitignored, so your names never become public:

```
# ci/disclosure-denylist.local
\batlas\b
mycorp-internal
RG-PRODUCTION
```

The guard cannot catch a name it has never seen and has no pattern for. Read
your diff.

---

## Commit messages

Explain **why**, not what — the diff already says what. If you fixed a bug, say
what the wrong behaviour was and what it would have cost. If you made a
non-obvious tradeoff, say what you gave up.

Do not name real hosts or private systems in a commit message. History is
public and is not practically rewritable once cloned.

---

## Tests

- Prove the behaviour, not the implementation.
- Pin both directions of a classifier. A rule that demotes findings needs a test
  that the wrong things are *not* demoted — the false-positive direction is
  usually the one that matters.
- Use `internal/clock`, never `time.Now()`, so tests are deterministic.
- Shell fragments embedded in Go get a syntax check. A typo in a verify script
  makes every fix roll itself back forever, with nothing to indicate the script
  rather than the host is at fault.

---

## Scope

Out of scope, permanently:

- Online password brute-forcing.
- Exploitation. Validation proves a condition; it does not weaponise it.
- Vendoring Nmap — its NPSL licence is GPL-incompatible.
- Unattended application of amber or red fixes.

## License

Contributions are accepted under GPL-3.0.
