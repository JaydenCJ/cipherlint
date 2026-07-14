#!/usr/bin/env bash
# Gate a deploy on cipherlint: fail the pipeline when a TLS config regresses
# below the intermediate profile. Pin the table date so the gate's meaning
# never changes behind your back; bump the pin deliberately, in a commit.
#
# Usage: bash examples/ci-gate.sh <config-file>...
set -euo pipefail

PROFILE="intermediate@2026-01"   # pinned vintage: bump on purpose, not by accident

if [ "$#" -eq 0 ]; then
  echo "usage: bash examples/ci-gate.sh <config-file>..." >&2
  exit 2
fi

# Use the binary built at the repository root if present, else PATH.
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/cipherlint"
[ -x "$BIN" ] || BIN="cipherlint"

# --fail-on warning: errors AND profile violations block the deploy;
# info-level recommendations are reported but do not gate.
"$BIN" lint --profile "$PROFILE" --fail-on warning --format markdown "$@"
