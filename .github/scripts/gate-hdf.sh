#!/bin/bash
# The scan gate: normalizes every scanner's SARIF into HDF and applies the
# committed threshold templates — the threshold verdict, not the scanners'
# exit codes, is what fails CI. This pipeline normalizes and gates its own
# scan data through HDF, as an exemplar of how to use HDF in a pipeline.
#
# The CLI is the last *released* hdf binary, pinned by version + sha256 —
# deliberately not built from the commit under test, so a CLI bug in a PR
# cannot fail (or skew) its own gate. Bump the pin when a release lands.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
SA="${SCAN_DIR:-$ROOT/scan-artifacts}"
HS="${HDF_SCANS_DIR:-$ROOT/hdf-scans}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
THRESHOLDS="$ROOT/.github/hdf-thresholds"

if [ -z "${HDF_BIN:-}" ]; then
  : "${HDF_CLI_VERSION:?set HDF_CLI_VERSION+HDF_CLI_SHA256 or HDF_BIN}"
  : "${HDF_CLI_SHA256:?set HDF_CLI_VERSION+HDF_CLI_SHA256 or HDF_BIN}"
  curl -fsSL -o /tmp/hdf-cli.tar.gz \
    "https://github.com/mitre/hdf-libs/releases/download/v${HDF_CLI_VERSION}/hdf_${HDF_CLI_VERSION}_linux_amd64.tar.gz"
  echo "${HDF_CLI_SHA256}  /tmp/hdf-cli.tar.gz" | sha256sum -c -
  tar xzf /tmp/hdf-cli.tar.gz -C /tmp hdf
  HDF_BIN=/tmp/hdf
fi

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
cat "$SA"/manifest-*.txt | while read -r f; do
  if ! test -s "$SA/$f"; then
    echo "::error::expected scan artifact missing or empty: $f"
    exit 1
  fi
done

FAIL=0
{
  echo "## Scan gate (HDF thresholds)"
  echo ""
  echo "| Scan | Threshold |"
  echo "|---|---|"
} >> "$SUMMARY"
for f in "$SA"/*.sarif; do
  base=$(basename "$f" .sarif)
  # govulncheck carries reachability in its severity levels and only gates
  # on called symbols — see hdf-thresholds/govulncheck.yaml.
  case "$base" in
    govulncheck-*) T="$THRESHOLDS/govulncheck.yaml" ;;
    *)             T="$THRESHOLDS/scans.yaml" ;;
  esac
  echo "::group::hdf $base"
  "$HDF_BIN" convert "$f" -o "$HS/$base.hdf.json"
  "$HDF_BIN" validate "$HS/$base.hdf.json"
  verdict="pass"
  "$HDF_BIN" validate threshold "$HS/$base.hdf.json" -T "$T" || { verdict="FAIL"; FAIL=1; }
  echo "::endgroup::"
  echo "| $base | $verdict |" >> "$SUMMARY"
done
exit $FAIL
