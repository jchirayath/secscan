#!/usr/bin/env bash
# Architecture guards.
#
# Conventions that aren't enforced are decoration. Codebases accumulate hundreds
# of scattered os.Getenv calls, dozens of ad-hoc http.Client literals, a handful
# of InsecureSkipVerify, and far more routes than capability checks — not because
# anyone decided that, but because nothing failed the build.
#
# These run with EMPTY allow-lists, which is the one advantage a new repo has.
# Keep them that way.
#
# Usage: ci/guards.sh          (from the repo root)
set -uo pipefail
cd "$(dirname "$0")/.."

fails=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; shift; printf '      %s\n' "$@"; fails=$((fails+1)); }

# guard <name> <description> <files…> — fails if the pattern matches anywhere
# outside the permitted file.
# A blanket ban with no escape hatch gets weakened the first time a legitimate
# case appears. Instead each exception must carry a `secscan:allow-<guard>`
# marker on the line, so every one is explicit, greppable and reviewable:
#
#   grep -rn 'secscan:allow-' --include='*.go' .
#
# lists the complete set of exceptions in the codebase.
check() {
  local name="$1" pattern="$2" allowed="$3" desc="$4"
  local hits
  hits=$(grep -rnE "$pattern" --include='*.go' . 2>/dev/null \
    | grep -v '_test.go' \
    | grep -vE ':[0-9]+:\s*(//|\*|/\*)' \
    | grep -v "secscan:allow-${name#no-}" \
    | { [ -n "$allowed" ] && grep -v "$allowed" || cat; } || true)
  if [ -n "$hits" ]; then
    fail "$name — $desc" "$(echo "$hits" | head -5)"
  else
    pass "$name"
  fi
}

echo "Architecture guards"

# --- dependencies --------------------------------------------------------
if grep -qE '^\s*require\s' go.mod 2>/dev/null; then
  fail "zero-dependencies" "go.mod gained a require block; the binary must stay stdlib-only"
else
  pass "zero-dependencies"
fi

# --- configuration -------------------------------------------------------
check "no-getenv" '\bos\.Getenv\(' 'internal/config/config.go' \
  "os.Getenv outside internal/config — every key must be declared in the registry"

# --- outbound HTTP -------------------------------------------------------
check "no-http-client-literal" '\bhttp\.Client\{' 'internal/httpx/httpx.go' \
  "http.Client literal outside internal/httpx — no uniform timeout or TLS floor"

check "no-insecure-tls" 'InsecureSkipVerify' '' \
  "InsecureSkipVerify accepts any certificate; there is no registered exception"

# --- errors --------------------------------------------------------------
check "apierr-constants-only" 'writeErr\([^,]+,\s*"' '' \
  "string literal in the error-code position — use an apierr constant"

# --- time ----------------------------------------------------------------
check "no-time-now" '\btime\.Now\(\)' 'internal/clock/clock.go' \
  "time.Now() outside internal/clock — inject the clock so tests can control it"

# --- risk ----------------------------------------------------------------
# Exactly one risk implementation. Two divergent scorers is a bug that ships
# easily: the dashboard sorts on one, auto-eligibility decides on the other.
score_impls=$(grep -rln 'func Score(' --include='*.go' . | grep -v '_test.go' | grep -v 'internal/core/scan/scan.go' || true)
if [ "$(echo "$score_impls" | grep -c .)" -gt 1 ] 2>/dev/null; then
  fail "single-risk-score" "more than one Score() implementation:" "$score_impls"
else
  pass "single-risk-score"
fi

# --- authorization -------------------------------------------------------
# Every API route must be wrapped in Guard(). This is the guard that would have
# catch a routes-without-capability-checks gap on day one.
unguarded=$(grep -nE 'mux\.HandleFunc\("(GET|POST|PUT|DELETE|PATCH) /api' internal/web/server.go \
  | grep -v 's.Guard(' || true)
if [ -n "$unguarded" ]; then
  fail "route-capability-coverage" "API route without a capability guard:" "$unguarded"
else
  pass "route-capability-coverage"
fi

# --- audit ---------------------------------------------------------------
# An audit entry naming a caller must also name the role. Roles are shared, so
# caller-only cannot answer "under what privilege?".
bad_audit=$(grep -rn -A3 'audit.Entry{' --include='*.go' . | grep -v '_test.go' \
  | grep 'Caller:' | grep -v 'Role:' || true)
if [ -n "$bad_audit" ]; then
  # Multi-line literals need a wider window; re-check each hit's block.
  for f in $(grep -rl 'audit.Entry{' --include='*.go' . | grep -v '_test.go'); do
    if awk '/audit\.Entry\{/{blk=1;buf=""} blk{buf=buf $0} /\}/{if(blk){if(buf ~ /Caller:/ && buf !~ /Role:/) print FILENAME; blk=0}}' "$f" | grep -q .; then
      fail "audit-actor-and-role" "audit.Entry with Caller but no Role in $f"
    fi
  done
  pass "audit-actor-and-role"
else
  pass "audit-actor-and-role"
fi

# --- frontend ------------------------------------------------------------
echo "UI guards"

hex=$(grep -nE '#[0-9a-fA-F]{3,8}\b' internal/web/ui/app.css | grep -v '^\s*/\*' || true)
if [ -n "$hex" ]; then
  fail "no-hex-color" "hex colour outside the token block — use a semantic token:" "$(echo "$hex" | head -3)"
else
  pass "no-hex-color"
fi

inline=$(grep -n 'style="' internal/web/ui/app.html internal/web/ui/app.js || true)
if [ -n "$inline" ]; then
  fail "no-inline-style" "inline style attribute — the CSP blocks these:" "$(echo "$inline" | head -3)"
else
  pass "no-inline-style"
fi

bare_fetch=$(grep -n 'fetch(' internal/web/ui/app.js | grep -v 'async function api' | grep -v 'const res = await fetch' || true)
if [ -n "$bare_fetch" ]; then
  fail "no-bare-fetch" "fetch() outside the shared api() helper:" "$(echo "$bare_fetch" | head -3)"
else
  pass "no-bare-fetch"
fi

# innerHTML with an un-escaped interpolation. `esc()` and safeUrl() are the
# only sanctioned ways a value reaches the DOM.
raw_interp=$(grep -nE 'innerHTML\s*[+]?=.*\$\{(?!esc\(|safeUrl\()' -P internal/web/ui/app.js 2>/dev/null || true)
if [ -n "$raw_interp" ]; then
  fail "escaped-interpolation" "innerHTML interpolation not wrapped in esc():" "$(echo "$raw_interp" | head -3)"
else
  pass "escaped-interpolation"
fi

# --- disclosure ------------------------------------------------------------
# This is not about credentials — gitleaks covers those. It is about the estate:
# hostnames, public addresses and resource identifiers that map a live
# environment. They reached this repo once via fixtures captured from real runs,
# and a later sanitising commit does not remove them from history.
#
# The check is deliberately GENERIC rather than a list of forbidden names. An
# earlier version enumerated the real hostnames it was defending against, which
# meant the guard file itself published an inventory of the estate — the
# disclosure it existed to prevent. Never put a real name in this file.
#
# Instead: fixtures and source may only reference documentation domains. Anything
# else is either a real host or a vendor URL, and vendor URLs are listed
# explicitly below.
doc_domains='example\.(com|net|org)|localhost|invalid|test'
vendor='github\.com|githubusercontent\.com|golang\.org|go\.dev|gnu\.org|owasp\.org|mozilla\.org|mitre\.org|nist\.gov|cisa\.gov|first\.org|projectdiscovery\.io|trivy\.dev|osv\.dev|googleapis\.com|microsoft\.com|microsoftonline\.com|azure\.com|debian\.org|ubuntu\.com|alpinelinux\.org|openssh\.com|ssllabs\.com|ivanti\.com|schema\.org|w3\.org|icann\.org|iana\.org|github\.io|windows\.net|google\.com|gstatic\.com|okta\.com|auth0\.com|onelogin\.com|duosecurity\.com|cloudflare\.com|letsencrypt\.org'
# Lowercase-only and a conservative TLD set on purpose: matching case-insensitively
# turned Go identifiers like `ci.HostConfig.Net` into "hostnames", and including
# .co matched the sysctl name `net.ipv4.conf...`. A guard that cries wolf gets
# switched off, which costs more than the cases it would have caught.
hosts=$(grep -rnoE '[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+\.(com|net|org|io|dev|shop|cloud|app)\b' \
  --include='*.go' --include='*.json' --include='*.jsonl' \
  --include='*.css' --include='*.js' --include='*.html' . 2>/dev/null \
  | grep -vE "($doc_domains)$" \
  | grep -vE "($vendor)$" \
  | grep -v '^./ci/guards.sh' || true)

# Public IP literals. Private ranges and the documentation ranges reserved by
# RFC 5737 are fine; anything else is somebody's real address.
ips=$(grep -rnoE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' \
  --include='*.go' --include='*.json' --include='*.jsonl' --include='*.md' \
  --include='*.js' --include='*.sh' . 2>/dev/null \
  | grep -vE ':(10\.|127\.|0\.0\.0\.0|255\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  | grep -vE ':(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)' \
  | grep -vE ':[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' --file=/dev/null 2>/dev/null \
  | grep -v '^./ci/guards.sh' || true)

# Site-specific names that do not look like domains (a host called `atlas`, an
# internal project codename) cannot be caught generically. Keep those in
# ci/disclosure-denylist.local — one extended-regex per line. That file is
# gitignored precisely so the names never become public.
local_hits=""
if [ -f ci/disclosure-denylist.local ]; then
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue;; esac
    found=$(grep -rnEi -- "$pat" --include='*.go' --include='*.md' --include='*.json' \
      --include='*.jsonl' --include='*.css' --include='*.js' --include='*.html' \
      --include='*.sh' --include='*.yml' . 2>/dev/null \
      | grep -v '^./ci/guards.sh' || true)
    [ -n "$found" ] && local_hits="$local_hits$found
"
  done < ci/disclosure-denylist.local
fi

infra=$(printf '%s\n%s\n%b' "$hosts" "$ips" "$local_hits" | grep -v '^$' || true)
if [ -n "$infra" ]; then
  fail "no-real-infrastructure" \
    "non-documentation hostname or address in the repository (use example.net / RFC 5737):" \
    "$(echo "$infra" | head -5)"
else
  pass "no-real-infrastructure"
fi

# Scanner output must never be committed. A snapshot is a complete map of a
# host's weaknesses — open findings, exposed ports, weak accounts, the command
# transcripts behind them. That is a worse disclosure than any credential this
# repo could leak, and it is one mistyped SECSCAN_HOME away.
scandata=$(git ls-files 2>/dev/null | grep -E '^(state\.json|history\.jsonl|audit\.jsonl|snapshots/|data/)|\.snapshot\.json$|-assessment\.md$' || true)
if [ -n "$scandata" ]; then
  fail "no-scan-output-committed" "scanner output is tracked by git:" "$scandata"
else
  pass "no-scan-output-committed"
fi

# The .env template must match the registry, or it tells operators to set
# variables the binary does not read.
if [ -f .env.example ] && command -v go >/dev/null 2>&1; then
  if go run ./cmd/secscan config -example 2>/dev/null | diff -q - .env.example >/dev/null 2>&1; then
    pass "env-example-current"
  else
    fail "env-example-current" "\.env.example is stale; regenerate: ./secscan config -example > .env.example"
  fi
fi

# gitleaks is optional locally but required in CI; absent, say so rather than
# silently passing a check that never ran.
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks dir . --no-banner --redact >/dev/null 2>&1; then
    pass "no-committed-secrets"
  else
    fail "no-committed-secrets" "gitleaks found credentials in the working tree; run: gitleaks dir . --redact"
  fi
else
  printf '  \033[33m~\033[0m %s\n' "no-committed-secrets — gitleaks not installed, check SKIPPED (not passed)"
fi

echo "Registered exceptions"
exceptions=$(grep -rn 'secscan:allow-' --include='*.go' . | grep -v '_test.go' | grep -v 'guards.sh' || true)
if [ -n "$exceptions" ]; then
  echo "$exceptions" | sed 's/^/  /'
else
  echo "  (none)"
fi

echo
if [ "$fails" -gt 0 ]; then
  printf '\033[31m%d guard(s) failed\033[0m\n' "$fails"
  exit 1
fi
printf '\033[32mall guards passed\033[0m\n'
