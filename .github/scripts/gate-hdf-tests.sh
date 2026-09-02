#!/bin/bash
# The test-results gate: normalizes every test job's JUnit XML into HDF and
# applies the committed threshold template. Runs `if: always()` so red runs
# are normalized too; the manifest checks keep an early-dead test job from
# yielding a vacuously green gate on an empty download.
#
# Artifacts arrive per-job (test-results-<lang>-<os>), each in its own
# subdirectory of TEST_DL_DIR — deliberately NOT merge-multiple: ubuntu and
# windows emit identically-named files.
set -euo pipefail
shopt -s nullglob

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
DL="${TEST_DL_DIR:-$ROOT/test-artifacts-dl}"
HS="${HDF_TESTS_DIR:-$ROOT/hdf-tests}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
THRESHOLD="$ROOT/.github/hdf-thresholds/tests.yaml"

# shellcheck source=lib-hdf-cli.sh
. "$ROOT/.github/scripts/lib-hdf-cli.sh"
resolve_hdf_bin

mkdir -p "$HS"
cd "$ROOT"

# All four test legs (lang x OS) must have reported in.
for m in tests-ts-ubuntu-latest tests-ts-windows-latest tests-go-ubuntu-latest tests-go-windows-latest; do
  manifest=$(find "$DL" -name "manifest-$m.txt" | head -1)
  if [ -z "$manifest" ] || ! test -s "$manifest"; then
    echo "::error::test manifest missing or empty: manifest-$m.txt — a test leg produced nothing"
    exit 1
  fi
  dir=$(dirname "$manifest")
  while read -r f; do
    if ! test -s "$dir/$f"; then
      echo "::error::expected JUnit file missing or empty: $f (leg $m)"
      exit 1
    fi
  done < "$manifest"
done

FAIL=0
COUNT=0
{
  echo "## Test gate (HDF thresholds)"
  echo ""
  echo "| Test results | Threshold |"
  echo "|---|---|"
} >> "$SUMMARY"
for f in "$DL"/*/*.xml; do
  leg=$(basename "$(dirname "$f")")
  base="$leg-$(basename "$f" .xml)"
  COUNT=$((COUNT + 1))
  echo "::group::hdf $base"
  verdict="ERROR"
  if "$HDF_BIN" convert "$f" -o "$HS/$base.hdf.json" && "$HDF_BIN" validate "$HS/$base.hdf.json"; then
    verdict="pass"
    "$HDF_BIN" validate threshold "$HS/$base.hdf.json" -T "$THRESHOLD" || verdict="FAIL"
  fi
  [ "$verdict" != "pass" ] && FAIL=1
  echo "::endgroup::"
  echo "| $base | $verdict |" >> "$SUMMARY"
done
if [ "$COUNT" -eq 0 ]; then
  echo "::error::no JUnit files found after manifest checks — gate refuses to pass vacuously"
  exit 1
fi
exit $FAIL
