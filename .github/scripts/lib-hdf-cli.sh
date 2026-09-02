#!/bin/bash
# Shared by the gate scripts: resolves HDF_BIN to the last *released* hdf
# CLI, pinned by version + sha256 — deliberately not built from the commit
# under test, so a CLI bug in a PR cannot fail (or skew) its own gate.
# Bump the pin when a release lands (release skill, Phase 9).
# Callers may pre-set HDF_BIN (local runs) to skip the download.

resolve_hdf_bin() {
  if [ -n "${HDF_BIN:-}" ]; then
    return 0
  fi
  : "${HDF_CLI_VERSION:?set HDF_CLI_VERSION+HDF_CLI_SHA256 or HDF_BIN}"
  : "${HDF_CLI_SHA256:?set HDF_CLI_VERSION+HDF_CLI_SHA256 or HDF_BIN}"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/hdf-cli.tar.gz" \
    "https://github.com/mitre/hdf-libs/releases/download/v${HDF_CLI_VERSION}/hdf_${HDF_CLI_VERSION}_linux_amd64.tar.gz"
  echo "${HDF_CLI_SHA256}  $tmp/hdf-cli.tar.gz" | sha256sum -c -
  tar xzf "$tmp/hdf-cli.tar.gz" -C "$tmp" hdf
  HDF_BIN="$tmp/hdf"
}
