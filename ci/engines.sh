#!/usr/bin/env bash
# Engine pins: list them, and install exactly those versions for the contract
# tests (internal/core/engine/contract_test.go).
#
# The pins live in internal/core/engine/install.go, because that is what the
# product installs on a target. Reading them from there — rather than keeping a
# second list here — means a version bump (by Renovate or by hand) changes what
# CI installs and tests in the same commit. Two lists would let the tested
# version and the shipped version drift apart, which is the one thing a test
# gate for automated bumps must not allow.
#
# Trivy is the exception: the product installs it from Aqua's package
# repository (unpinned), so CI pins it here, and Renovate moves this pin.
#
# Usage:
#   ci/engines.sh versions                 print "<engine> <version>" for every pin
#   ci/engines.sh install DIR              install the pinned versions into DIR/bin
#   ci/engines.sh install DIR --latest     install upstream's latest releases instead
#                                          (the weekly canary: does today's upstream
#                                          still satisfy our adapters?)
#
# Linux only (amd64/arm64): it is the CI and container platform. On macOS use
# Homebrew and accept that you are testing whatever version it ships.
set -euo pipefail
cd "$(dirname "$0")/.."

# renovate: datasource=github-releases depName=aquasecurity/trivy
TRIVY_VERSION=0.76.2

INSTALL_GO=internal/core/engine/install.go

pin() { # pin <const-name> — the quoted value of a const in install.go
  local v
  v=$(sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "$INSTALL_GO" | head -1)
  [ -n "$v" ] || { echo "engines.sh: $1 not found in $INSTALL_GO" >&2; exit 1; }
  echo "$v"
}

versions() {
  echo "gitleaks $(pin gitleaksVersion)"
  echo "osv-scanner $(pin osvVersion)"
  echo "nuclei $(pin nucleiVersion)"
  echo "testssl $(pin testsslVersion)"
  echo "trivy $TRIVY_VERSION"
}

# latest <owner/repo> — newest release tag without the leading v. Authenticated
# when GITHUB_TOKEN is set (CI), otherwise the unauthenticated rate limit.
latest() {
  local auth=()
  [ -n "${GITHUB_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
  local v
  v=$(curl -fsSL "${auth[@]}" "https://api.github.com/repos/$1/releases/latest" \
    | tr ',' '\n' | sed -nE 's/.*"tag_name":[[:space:]]*"v?([^"]+)".*/\1/p' | head -1)
  # An empty answer (rate limit, outage) must stop the run: carrying on would
  # build a download URL with no version in it and fail somewhere confusing.
  [ -n "$v" ] || { echo "engines.sh: could not resolve the latest release of $1" >&2; exit 1; }
  echo "$v"
}

fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }

# verify <file> <sums-file> <name-in-sums> — the release's own checksum list.
# This catches a corrupted or swapped asset; it does not defend against a
# compromised release (the sums ship alongside), which is what the Renovate
# cooldown is for.
verify() {
  local want
  want=$(awk -v n="$3" '$2==n || $2=="*"n {print $1}' "$2" | head -1)
  [ -n "$want" ] || { echo "no checksum for $3 in $(basename "$2")" >&2; exit 1; }
  echo "$want  $1" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $3" >&2; exit 1; }
}

install_all() {
  local dir="$1" mode="${2:-}"
  [ "$(uname -s)" = Linux ] || { echo "engines.sh install is Linux-only" >&2; exit 1; }
  local a gl os nu tr
  case "$(uname -m)" in
    x86_64) a=amd64 gl=x64 tr=64bit ;;
    aarch64|arm64) a=arm64 gl=arm64 tr=ARM64 ;;
    *) echo "unsupported arch $(uname -m)" >&2; exit 1 ;;
  esac

  local v_gl v_osv v_nu v_ts v_tr
  if [ "$mode" = "--latest" ]; then
    v_gl=$(latest gitleaks/gitleaks); v_osv=$(latest google/osv-scanner)
    v_nu=$(latest projectdiscovery/nuclei); v_ts=$(latest testssl/testssl.sh)
    v_tr=$(latest aquasecurity/trivy)
  else
    v_gl=$(pin gitleaksVersion); v_osv=$(pin osvVersion)
    v_nu=$(pin nucleiVersion); v_ts=$(pin testsslVersion); v_tr=$TRIVY_VERSION
  fi

  mkdir -p "$dir/bin"
  local tmp; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN

  gh_dl=https://github.com
  # gitleaks
  local f="gitleaks_${v_gl}_linux_${gl}.tar.gz"
  fetch "$gh_dl/gitleaks/gitleaks/releases/download/v$v_gl/$f" "$tmp/$f"
  fetch "$gh_dl/gitleaks/gitleaks/releases/download/v$v_gl/gitleaks_${v_gl}_checksums.txt" "$tmp/gl.sums"
  verify "$tmp/$f" "$tmp/gl.sums" "$f"
  tar -xzf "$tmp/$f" -C "$dir/bin" gitleaks

  # osv-scanner
  f="osv-scanner_linux_${a}"
  fetch "$gh_dl/google/osv-scanner/releases/download/v$v_osv/$f" "$tmp/$f"
  fetch "$gh_dl/google/osv-scanner/releases/download/v$v_osv/osv-scanner_SHA256SUMS" "$tmp/osv.sums"
  verify "$tmp/$f" "$tmp/osv.sums" "$f"
  install -m 0755 "$tmp/$f" "$dir/bin/osv-scanner"

  # nuclei
  f="nuclei_${v_nu}_linux_${a}.zip"
  fetch "$gh_dl/projectdiscovery/nuclei/releases/download/v$v_nu/$f" "$tmp/$f"
  fetch "$gh_dl/projectdiscovery/nuclei/releases/download/v$v_nu/nuclei_${v_nu}_checksums.txt" "$tmp/nu.sums"
  verify "$tmp/$f" "$tmp/nu.sums" "$f"
  (cd "$tmp" && unzip -q -o "$f" nuclei) && install -m 0755 "$tmp/nuclei" "$dir/bin/nuclei"

  # trivy
  f="trivy_${v_tr}_Linux-${tr}.tar.gz"
  fetch "$gh_dl/aquasecurity/trivy/releases/download/v$v_tr/$f" "$tmp/$f"
  fetch "$gh_dl/aquasecurity/trivy/releases/download/v$v_tr/trivy_${v_tr}_checksums.txt" "$tmp/tr.sums"
  verify "$tmp/$f" "$tmp/tr.sums" "$f"
  tar -xzf "$tmp/$f" -C "$dir/bin" trivy

  # testssl.sh ships no checksum list; it is a source tree at a tag. Installed
  # the same way install.go installs it on a target (tree + symlink), so the
  # contract test exercises the real layout, data files included.
  fetch "$gh_dl/testssl/testssl.sh/archive/refs/tags/v$v_ts.tar.gz" "$tmp/t.tgz"
  rm -rf "$dir/testssl.sh" && mkdir -p "$dir/testssl.sh"
  tar -xzf "$tmp/t.tgz" -C "$dir/testssl.sh" --strip-components=1
  ln -sf "$dir/testssl.sh/testssl.sh" "$dir/bin/testssl.sh"

  echo "installed into $dir/bin:"
  printf '  gitleaks %s\n  osv-scanner %s\n  nuclei %s\n  testssl %s\n  trivy %s\n' \
    "$v_gl" "$v_osv" "$v_nu" "$v_ts" "$v_tr"
}

case "${1:-}" in
  versions) versions ;;
  install) [ -n "${2:-}" ] || { echo "usage: $0 install DIR [--latest]" >&2; exit 2; }
           install_all "$2" "${3:-}" ;;
  *) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
