#!/bin/bash
# Per-package ESLint, emitted as SARIF for the HDF gate, via arg passthrough
# to each package's own lint script (identical lint scope to a plain
# `pnpm run lint`). eslint exit 1 means findings — judged by gate-hdf's
# threshold; >=2 is a fatal tool error and fails this script.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${SCAN_DIR:-$ROOT/scan-artifacts}"
FMT="$ROOT/node_modules/@microsoft/eslint-formatter-sarif/sarif.js"

mkdir -p "$OUT"
cd "$ROOT"
FAIL=0
for dir in $(pnpm -r --filter=!hdf-cli list --depth -1 --parseable); do
  [ "$dir" = "$ROOT" ] && continue
  grep -q '"lint"' "$dir/package.json" || continue
  name=$(basename "$dir")
  echo "::group::eslint $name"
  rc=0
  (cd "$dir" && pnpm run lint --format "$FMT" --output-file "$OUT/eslint-$name.sarif") || rc=$?
  echo "::endgroup::"
  if [ "$rc" -ge 2 ]; then
    echo "::error::eslint tool failure in $name (exit $rc)"
    FAIL=1
  fi
  if ! test -s "$OUT/eslint-$name.sarif"; then
    echo "::error::missing eslint SARIF for $name"
    FAIL=1
  fi
  echo "eslint-$name.sarif" >> "$OUT/manifest-ts.txt"
done
exit $FAIL
