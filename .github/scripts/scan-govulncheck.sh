#!/bin/bash
# Per-module govulncheck, emitted as SARIF for the HDF gate. SARIF mode
# exits 0 even with findings (by design — downstream policy decides; see
# .github/hdf-thresholds/govulncheck.yaml), so any nonzero exit is a tool
# failure. Modules are driven by go.work (govulncheck has no workspace
# mode, golang/go#66863).
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${SCAN_DIR:-$ROOT/scan-artifacts}"
if [ -z "${GOVULNCHECK_BIN:-}" ]; then
  go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION:?set GOVULNCHECK_VERSION or GOVULNCHECK_BIN}"
  GOVULNCHECK_BIN=govulncheck
fi

mkdir -p "$OUT"
cd "$ROOT"
FAIL=0
for dir in $(go work edit -json | jq -r '.Use[].DiskPath'); do
  name=$(echo "${dir#./}" | tr '/' '-')
  echo "::group::govulncheck $dir"
  rc=0
  (cd "$dir" && "$GOVULNCHECK_BIN" -format sarif ./... > "$OUT/govulncheck-$name.sarif") || rc=$?
  echo "::endgroup::"
  if [ "$rc" -ne 0 ]; then
    echo "::error::govulncheck tool failure in $dir (exit $rc)"
    FAIL=1
  fi
  if ! test -s "$OUT/govulncheck-$name.sarif"; then
    echo "::error::missing govulncheck SARIF for $dir"
    FAIL=1
  fi
  echo "govulncheck-$name.sarif" >> "$OUT/manifest-go.txt"
done
exit $FAIL
