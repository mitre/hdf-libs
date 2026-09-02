#!/bin/bash
# Workflow-file static analysis, emitted as SARIF for the HDF gate.
# --no-exit-codes: exit is nonzero only on tool failure; findings flow to
# the SARIF and are judged by gate-hdf's threshold check.
#
# The binary comes from zizmor's GitHub release, pinned by version + sha256
# (same discipline as the hdf CLI pin; the digest is also recorded on the
# release asset itself). Local runs may pre-set ZIZMOR_CMD to skip this.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${SCAN_DIR:-$ROOT/scan-artifacts}"
ZIZMOR_VERSION="${ZIZMOR_VERSION:-1.30.0}"
ZIZMOR_SHA256="${ZIZMOR_SHA256:-ec8c95cd800845abb9bbc5f377ec7c57d2eb8e2386a00a201d3a74ee4092e5ed}"

if [ -z "${ZIZMOR_CMD:-}" ]; then
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/zizmor.tar.gz" \
    "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
  echo "${ZIZMOR_SHA256}  $tmp/zizmor.tar.gz" | sha256sum -c -
  tar xzf "$tmp/zizmor.tar.gz" -C "$tmp"
  ZIZMOR_CMD="$(find "$tmp" -name zizmor -type f | head -1)"
fi

mkdir -p "$OUT"
cd "$ROOT"
$ZIZMOR_CMD --no-exit-codes --format sarif .github/workflows/ > "$OUT/zizmor.sarif"
test -s "$OUT/zizmor.sarif"
echo "zizmor.sarif" > "$OUT/manifest-workflows.txt"
