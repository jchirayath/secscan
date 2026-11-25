#!/usr/bin/env bash
# The update gate: everything a pull request must pass before it merges —
# including the ones a bot opens.
#
# One script, run identically on a laptop and in CI (the engineering standard's
# "one gate" rule), so "it passed locally" and "it passed CI" mean the same
# thing. Automated dependency PRs are only safe to merge unattended when this
# gate is the thing that says yes.
#
#   ci/gate.sh              vet, tests (incl. the binary smoke test), guards
#   ci/gate.sh --engines    also the engine contract tests; needs the real engines
#                           on PATH (ci/engines.sh install DIR) and network
#
# Steps, and why each is here:
#   go vet           catches the API misuse a toolchain bump newly flags
#   go test -race    unit + e2e + cmd/secscan smoke test (builds the binary,
#                    runs `scan`, `plan`, `-report`, `serve` + /healthz + API)
#   ci/guards.sh     architecture guards; must stay green
#   go build         the release build, trimmed and version-stamped
#   contracts        the pinned engines' real output through the real adapters
set -uo pipefail
cd "$(dirname "$0")/.."

fails=0
step() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; fails=$((fails+1)); }

step "go vet"
if go vet ./...; then ok "vet"; else bad "vet"; fi

# Formatting is reported but not yet blocking: four files on public-release
# predate the check (internal/apierr, internal/core/exec/record_test.go and two
# internal/web tests). Once they are gofmt'd, set GATE_GOFMT_STRICT=1 in CI.
step "gofmt"
unformatted=$(gofmt -l cmd internal ci 2>/dev/null || true)
if [ -z "$unformatted" ]; then ok "gofmt"
elif [ "${GATE_GOFMT_STRICT:-0}" = 1 ]; then bad "gofmt — run gofmt -w:"; echo "$unformatted" | sed 's/^/      /'
else printf '  \033[33m~\033[0m gofmt — not yet blocking; unformatted:\n'; echo "$unformatted" | sed 's/^/      /'
fi

step "go test -race ./..."
if go test -race -count=1 ./...; then ok "tests (incl. binary smoke test)"; else bad "tests"; fi

step "ci/guards.sh"
if bash ci/guards.sh; then ok "guards"; else bad "guards"; fi

step "go build"
out=$(mktemp -d)
if go build -trimpath -ldflags "-s -w -X main.Version=gate" -o "$out/secscan" ./cmd/secscan \
   && [ "$("$out/secscan" version)" = "secscan gate" ]; then ok "build + version stamp"; else bad "build"; fi
rm -rf "$out"

if [ "${1:-}" = "--engines" ]; then
  step "engine contract tests"
  ci/engines.sh versions | sed 's/^/  pinned: /'
  for b in trivy gitleaks osv-scanner nuclei testssl.sh; do
    command -v "$b" >/dev/null && printf '  on PATH: %s\n' "$("$b" --version 2>/dev/null | head -1 || echo "$b")"
  done
  if SECSCAN_ENGINE_CONTRACT=1 go test -count=1 -run Contract -v ./internal/core/engine/; then
    ok "engine contracts"
  else
    bad "engine contracts"
  fi
fi

echo
if [ "$fails" -gt 0 ]; then printf '\033[31mgate failed: %d step(s)\033[0m\n' "$fails"; exit 1; fi
printf '\033[32mgate passed\033[0m\n'
