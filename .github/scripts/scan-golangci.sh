#!/bin/bash
# Per-module golangci-lint, emitted as SARIF for the HDF gate while the
# human-readable text stays on stdout from the same run. Exit 1 is the
# documented issues-exit-code (findings — judged by gate-hdf's threshold);
# any other nonzero exit is a tool failure and fails this script.
# Modules are driven by go.work so new ones are picked up automatically
# (golangci-lint refuses multi-module invocations).
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${SCAN_DIR:-$ROOT/scan-artifacts}"
if [ -z "${GOLANGCI_BIN:-}" ]; then
  # go install is kept over the faster binary-install script deliberately:
  # module downloads are verified against the Go checksum database, which is
  # a stronger supply-chain guarantee, and the setup-go module cache makes
  # the compile cost a one-time event per cache key.
  go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION:?set GOLANGCI_LINT_VERSION or GOLANGCI_BIN}"
  GOLANGCI_BIN=golangci-lint
fi

mkdir -p "$OUT"
cd "$ROOT"
FAIL=0
for dir in $(go work edit -json | jq -r '.Use[].DiskPath' | tr -d '\r'); do
  name=$(echo "${dir#./}" | tr '/' '-')
  echo "::group::golangci-lint $dir"
  rc=0
  (cd "$dir" && "$GOLANGCI_BIN" run --output.text.path stdout --output.sarif.path "$OUT/golangci-$name.sarif" ./...) || rc=$?
  echo "::endgroup::"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    echo "::error::golangci-lint tool failure in $dir (exit $rc)"
    FAIL=1
  fi
  if ! test -s "$OUT/golangci-$name.sarif"; then
    echo "::error::missing golangci SARIF for $dir"
    FAIL=1
  fi
  echo "golangci-$name.sarif" >> "$OUT/manifest-go.txt"
done
exit $FAIL
