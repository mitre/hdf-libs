#!/bin/bash
# Workflow-file static analysis, emitted as SARIF for the HDF gate.
# --no-exit-codes: exit is nonzero only on tool failure; findings flow to
# the SARIF and are judged by gate-hdf's threshold check.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${SCAN_DIR:-$ROOT/scan-artifacts}"
ZIZMOR_VERSION="${ZIZMOR_VERSION:-1.30.0}"
ZIZMOR_CMD="${ZIZMOR_CMD:-pipx run zizmor==$ZIZMOR_VERSION}"

mkdir -p "$OUT"
cd "$ROOT"
$ZIZMOR_CMD --no-exit-codes --format sarif .github/workflows/ > "$OUT/zizmor.sarif"
test -s "$OUT/zizmor.sarif"
echo "zizmor.sarif" > "$OUT/manifest-workflows.txt"
