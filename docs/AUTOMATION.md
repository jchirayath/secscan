# Keeping secscan current

secscan updates itself through pull requests. Nothing merges unless the test
gate passes, and changes that affect what secscan does on a target always get a
human review. The setup follows the engineering standard: Renovate, grouped and
weekly, with a 7-day cooldown (SUP-1, CLEAN-10); actions pinned to a SHA
(SEC-17); one rolling issue per weekly check (the sources-weekly pattern).

## What runs, and when

| Piece | Schedule | What it does | Output |
|---|---|---|---|
| **Renovate** (`.github/renovate.json5`) | Mondays before 06:00 UTC; vulnerability fixes at any time | Bumps the Go toolchain (`go` in go.mod), GitHub Actions (SHA + version comment), the engines secscan installs on targets (`renovate:`-marked constants in `internal/core/engine/install.go`), and CI tools (trivy in `ci/engines.sh`, gitleaks and zizmor in `ci.yml`, govulncheck) | One PR per update, with the upstream release notes |
| **ci** (`.github/workflows/ci.yml`) | Every push and PR | `gate`: gitleaks over history, then `ci/gate.sh`. `engines`: installs the pinned engines and runs the engine contract tests. `workflows`: zizmor | Required checks |
| **upstream-weekly** (`.github/workflows/upstream-weekly.yml`) | Mondays 13:00 UTC | `canary`: contract tests against every engine's **latest** release. `report`: `ci/upstream.sh`, which covers release-note lines touching flags or output, new gitleaks rules, new nuclei CVE templates, Go support and govulncheck, and the candidate engines in TOOL-LANDSCAPE | One issue labelled `upstream-watch`, opened, updated, then closed when nothing needs a human |

## What merges on its own, and what waits for you

| Update | Automerge? | Why |
|---|---|---|
| Go **patch** release | yes, once green | Stdlib security and bug fixes. The gate exercises the whole binary. |
| Go **minor** (e.g. 1.24 → 1.27) | no (`needs-review`) | It changes language and stdlib behaviour. Go 1.24 is out of support, so merge this one soon. |
| Actions digest, patch or minor | yes, once green | They run only in CI, and zizmor lints them. |
| Actions **major** | no | Inputs and runtime can change. |
| CI tools (trivy pin, gitleaks, zizmor, govulncheck) patch or minor | yes, once green | They never ship. |
| **Engines** installed on targets (gitleaks, osv-scanner, nuclei, testssl.sh) | **never** (`engine`, `needs-review`, plus `breaking` for a major) | They run as root on hosts you own, and every finding comes from their output. The contract tests show the adapter still parses. They can't show the release is trustworthy. |
| A new engine *capability* or a new tool | not a PR | It's listed in the upstream-watch issue. A person opens a feature issue, then a PR with the adapter, fixture, contract test and install pin. |
| Vulnerability fixes (OSV or GitHub alerts) | follow the rules above, but **skip the cooldown** | So VULN-2 deadlines can be met (SUP-1 exemption). |

Detection content that engines fetch while they run (the trivy DB, nuclei
templates) needs no PR. The weekly issue reports what arrived. gitleaks rules
are compiled into the binary, so they arrive with the engine bump, and the issue
lists which rules were added or removed.

## The gate

`ci/gate.sh` runs the same way on a laptop and in CI:

- `go vet ./...`
- `gofmt`: reported only for now. Four files on public-release predate the
  check. Format them, then set `GATE_GOFMT_STRICT=1` in CI.
- `go test -race ./...`, which includes `cmd/secscan/smoke_test.go`. That test
  builds the real binary, runs `version`, `scan -json` (native collectors),
  `plan` and `scan -report -`, then starts `serve` and checks `/healthz`,
  `/api/overview`, `/api/features`, `/api/me`, `/`, the assets, and a clean
  SIGINT shutdown.
- `ci/guards.sh`
- a trimmed, version-stamped release build

`ci/gate.sh --engines` adds `internal/core/engine/contract_test.go`. These tests
run the real trivy, trivy-image, osv-scanner, gitleaks, nuclei and testssl.sh
against planted fixtures. Each fixture contains something the engine must find
(for example, a lodash version with known CVEs, a credential-shaped token, or a
canary nuclei template served over TLS). An engine bump that changes a flag or
an output shape fails here. The tests are opt-in (`SECSCAN_ENGINE_CONTRACT=1`)
because they need network access and about a minute. With the variable set, a
missing engine binary counts as a failure, not a skip.

```
ci/engines.sh versions                     # the pins, read from install.go
ci/engines.sh install /tmp/eng             # Linux: install the pinned versions (checksum-verified)
ci/engines.sh install /tmp/eng --latest    # or upstream's latest releases (the canary)
PATH=/tmp/eng/bin:$PATH ci/gate.sh --engines
```

## Turning it on (one-time, in GitHub)

1. **Renovate.** Install the Mend Renovate GitHub App on this repository only.
   It reads `.github/renovate.json5`. The first run opens a *Dependency
   Dashboard* issue. Renovate targets the default branch, so once
   `public-release` is pushed and is the line you deploy, either make it the
   default branch or add `baseBranchPatterns: ["public-release"]` to the
   config.
2. **Branch protection** on the default branch: require the status checks
   `gate`, `engines` and `workflows`, and require branches to be up to date.
   Automerge goes through this (`platformAutomerge`), so red never merges.
   Under *Settings → General*, enable *Allow auto-merge*.
3. **Actions permissions.** Under *Settings → Actions → General*, keep
   *Workflow permissions* at read-only. Each job asks for what it needs: only
   `upstream-weekly/report` gets `issues: write`. No secrets are needed, because
   both workflows use `GITHUB_TOKEN`.
4. **Labels.** Renovate and the weekly job create theirs (`dependencies`,
   `engine`, `needs-review`, `breaking`, `security`, `upstream-watch`) on first
   use.
5. Optional: enable *Dependabot alerts* (Settings → Code security). Renovate's
   `vulnerabilityAlerts` reads them to raise security PRs without the
   cooldown.

## Outside this repository

The container image that runs secscan on the deployment host is built from a
Dockerfile in the deployment repository, not this one, on an `alpine` base. It
needs its own Renovate config there, with the `dockerfile` manager and
`pinDigests: true` (SEC-16). The binary it copies in follows this repository's
releases.
