#!/bin/bash
# Gathers each TS package's vitest JUnit output (written per-package as
# test-results/junit.xml) into one directory with a manifest for the test
# gate. Runs `if: always()` so the failing run — exactly the one whose HDF
# evidence matters — still ships its results.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${TEST_DIR:-$ROOT/test-artifacts}"
OS_TAG="${OS_TAG:?set OS_TAG (e.g. ubuntu-latest)}"

mkdir -p "$OUT"
cd "$ROOT"
FOUND=0
for f in hdf-*/test-results/junit.xml site/test-results/junit.xml; do
  [ -s "$f" ] || continue
  pkg=$(echo "$f" | cut -d/ -f1)
  cp "$f" "$OUT/ts-$pkg.xml"
  echo "ts-$pkg.xml" >> "$OUT/manifest-tests-ts-$OS_TAG.txt"
  FOUND=$((FOUND + 1))
done
if [ "$FOUND" -eq 0 ]; then
  echo "::error::no vitest JUnit outputs found — the reporter flags did not take effect"
  exit 1
fi
echo "collected $FOUND JUnit files"
