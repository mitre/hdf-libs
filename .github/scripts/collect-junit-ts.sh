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

# Assert the COUNT, not just non-zero. Each package configures the junit
# reporter in its own vitest.config.ts, so a new package that omits the block —
# or one that stops emitting — would otherwise disappear from the gate's
# evidence silently, and a zero-check cannot see a 9-of-10 regression.
WANT=$(grep -l 'junit' -- */vitest.config.ts 2>/dev/null | wc -l | tr -d ' ')
if [ "$FOUND" -ne "$WANT" ]; then
  echo "::error::collected $FOUND JUnit files but $WANT packages configure the junit reporter"
  echo "::error::a package configured to emit produced nothing, or emits without being configured"
  exit 1
fi
echo "collected $FOUND JUnit files (all $WANT configured packages reported)"
