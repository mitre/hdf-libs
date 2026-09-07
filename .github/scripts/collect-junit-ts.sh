#!/bin/bash
# Gathers each TS package's vitest JUnit output (written per-package as
# test-results/junit.xml) into the one directory the test gate converts.
# Filenames carry the OS so both matrix legs can share that directory.
# Runs `if: always()` so the failing run — exactly the one whose HDF evidence
# matters — still ships its results.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
OS_TAG="${OS_TAG:?set OS_TAG (e.g. ubuntu-latest)}"
mkdir -p test-artifacts

FOUND=0
for f in hdf-*/test-results/junit.xml site/test-results/junit.xml; do
  [ -s "$f" ] || continue
  cp "$f" "test-artifacts/ts-$(echo "$f" | cut -d/ -f1)-$OS_TAG.xml"
  FOUND=$((FOUND + 1))
done

# Zero files means the reporter flags did not take effect — fail here rather
# than let the gate see a leg that silently produced nothing.
if [ "$FOUND" -eq 0 ]; then
  echo "::error::no vitest JUnit outputs found — the reporter flags did not take effect"
  exit 1
fi
echo "collected $FOUND JUnit files"
