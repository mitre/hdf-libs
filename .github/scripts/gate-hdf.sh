#!/bin/bash
# The scan gate: normalizes every scanner's SARIF into HDF and applies the
# committed threshold templates — the threshold verdict, not the scanners'
# exit codes, is what fails CI. This pipeline normalizes and gates its own
# scan data through HDF, as an exemplar of how to use HDF in a pipeline.
set -euo pipefail
shopt -s nullglob

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
SA="${SCAN_DIR:-$ROOT/scan-artifacts}"
HS="${HDF_SCANS_DIR:-$ROOT/hdf-scans}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
THRESHOLDS="$ROOT/.github/hdf-thresholds"

# shellcheck source=lib-hdf-cli.sh
. "$ROOT/.github/scripts/lib-hdf-cli.sh"
resolve_hdf_bin

mkdir -p "$HS"
cd "$ROOT"

# All three scanner families must have reported in — a failed enumeration
# (a jq/pnpm loop producing zero iterations) would otherwise skip a family
# without a trace.
for m in manifest-workflows.txt manifest-ts.txt manifest-go.txt; do
  if ! test -s "$SA/$m"; then
    echo "::error::scan manifest missing or empty: $m — a scanner family produced nothing"
    exit 1
  fi
done

# And every scan a producing job promised must actually be here — a
# tolerated scanner exit can never silently skip the gate.
while read -r f; do
  if ! test -s "$SA/$f"; then
    echo "::error::expected scan artifact missing or empty: $f"
    exit 1
  fi
done < <(cat "$SA"/manifest-*.txt)

FAIL=0
COUNT=0
{
  echo "## Scan gate (HDF thresholds)"
  echo ""
  echo "| Scan | Threshold |"
  echo "|---|---|"
} >> "$SUMMARY"
for f in "$SA"/*.sarif; do
  base=$(basename "$f" .sarif)
  COUNT=$((COUNT + 1))
  # govulncheck carries reachability in its severity levels and only gates
  # on called symbols — see hdf-thresholds/govulncheck.yaml.
  case "$base" in
    govulncheck-*) T="$THRESHOLDS/govulncheck.yaml" ;;
    *)             T="$THRESHOLDS/scans.yaml" ;;
  esac
  echo "::group::hdf $base"
  verdict="ERROR"
  if "$HDF_BIN" convert "$f" -o "$HS/$base.hdf.json" && "$HDF_BIN" validate "$HS/$base.hdf.json"; then
    verdict="pass"
    "$HDF_BIN" validate threshold "$HS/$base.hdf.json" -T "$T" || verdict="FAIL"
  fi
  [ "$verdict" != "pass" ] && FAIL=1
  echo "::endgroup::"
  echo "| $base | $verdict |" >> "$SUMMARY"
done
if [ "$COUNT" -eq 0 ]; then
  echo "::error::no scan SARIFs found after manifest checks — gate refuses to pass vacuously"
  exit 1
fi
exit $FAIL
