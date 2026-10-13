#!/usr/bin/env bash
# Copyright 2026 Luca Becci
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Read-only inspection of a signed macOS binary (Developer ID / ad-hoc).
# Does not modify the binary or touch the keychain.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-signed-binary>" >&2
  exit 2
fi

bin=$1
if [[ ! -f $bin ]]; then
  echo "error: not a file: $bin" >&2
  exit 2
fi

echo "=== codesign -dv ==="
codesign -dv --verbose=4 "$bin" 2>&1 || true

echo
echo "=== entitlements (XML) ==="
codesign -d --entitlements :- "$bin" 2>/dev/null || echo "(no entitlements blob)"

echo
echo "=== spctl assess (may fail for ad-hoc) ==="
spctl -a -vv "$bin" 2>&1 || true
