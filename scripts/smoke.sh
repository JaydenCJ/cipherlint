#!/usr/bin/env bash
# End-to-end smoke test for cipherlint: builds the binary, lints all four
# config dialects, checks exit codes, output formats, dated-profile
# resolution and the explain/profiles subcommands. No network, idempotent,
# finishes in seconds.
set -euo pipefail
# Note: assertions use `grep ... >/dev/null` rather than `grep -q`. With
# pipefail, -q exits at the first match and the still-writing producer can
# die of SIGPIPE, failing the pipeline at random. Plain grep reads to EOF.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  exit 1
}

BIN="$WORKDIR/cipherlint"

echo "1. build"
(cd "$ROOT" && go build -o "$BIN" ./cmd/cipherlint) || fail "go build failed"

echo "2. version matches manifest"
"$BIN" --version | grep -x "cipherlint 0.1.0" >/dev/null || fail "--version mismatch"

echo "3. legacy nginx config fails with cited errors"
set +e
OUT="$("$BIN" lint "$ROOT/examples/legacy-nginx.conf")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "legacy nginx should exit 1, got $CODE"
echo "$OUT" | grep "CL001" >/dev/null || fail "missing obsolete-protocol finding"
echo "$OUT" | grep "RC4"   >/dev/null || fail "missing RC4 finding"
echo "$OUT" | grep "RFC 8996" >/dev/null || fail "missing citation"

echo "4. clean intermediate nginx config passes"
"$BIN" lint "$ROOT/examples/intermediate-nginx.conf" >/dev/null \
  || fail "clean config should exit 0"

echo "5. dated tables flip the OCSP stapling advice"
OUT2023="$("$BIN" lint -p intermediate@2023-10 --format json "$ROOT/examples/legacy-nginx.conf" || true)"
OUT2026="$("$BIN" lint -p intermediate@2026-01 --format json "$ROOT/examples/legacy-nginx.conf" || true)"
echo "$OUT2023" | grep '"rule": "CL013"' >/dev/null && fail "2023 table should accept stapling on"
echo "$OUT2026" | grep '"rule": "CL013"' >/dev/null || fail "2026 table should flag stapling on"

echo "6. apache default-protocol trap is caught"
set +e
APACHE_OUT="$("$BIN" lint "$ROOT/examples/legacy-apache.conf")"
CODE=$?
set -e
[ "$CODE" -eq 1 ] || fail "apache example should exit 1, got $CODE"
echo "$APACHE_OUT" | grep "SSLProtocol not set" >/dev/null \
  || fail "apache implicit-default note missing"

echo "7. haproxy and Caddyfile dialects parse and fail as designed"
set +e
"$BIN" lint "$ROOT/examples/haproxy.cfg" >/dev/null 2>&1; H=$?
"$BIN" lint "$ROOT/examples/Caddyfile"   >/dev/null 2>&1; C=$?
set -e
[ "$H" -eq 1 ] || fail "haproxy example should exit 1, got $H"
[ "$C" -eq 1 ] || fail "Caddyfile example should exit 1, got $C"
("$BIN" lint "$ROOT/examples/haproxy.cfg" || true) | grep "CL009" >/dev/null \
  || fail "haproxy 1024-bit DH finding missing"

echo "8. JSON output is machine-readable"
JSON="$("$BIN" lint --format json "$ROOT/examples/legacy-nginx.conf" || true)"
echo "$JSON" | grep '"tool": "cipherlint"' >/dev/null || fail "json envelope missing"
echo "$JSON" | grep '"schema_version": 1' >/dev/null || fail "json schema_version missing"

echo "9. profiles and explain subcommands"
"$BIN" profiles | grep "intermediate@2026-01" >/dev/null || fail "profiles listing broken"
"$BIN" explain CL013 | grep "OCSP" >/dev/null || fail "explain CL013 broken"

echo "10. usage errors exit 2"
set +e
"$BIN" lint --format yaml "$ROOT/examples/legacy-nginx.conf" >/dev/null 2>&1
[ $? -eq 2 ] || fail "bad --format should exit 2"
"$BIN" lint -p paranoid "$ROOT/examples/legacy-nginx.conf" >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown profile should exit 2"
set -e

echo "SMOKE OK"
