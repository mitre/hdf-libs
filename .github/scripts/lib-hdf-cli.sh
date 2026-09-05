#!/bin/bash
# Shared by the gate scripts: resolves the hdf CLI the gate runs. Whichever
# source is used, it must NOT be a binary built from the commit under test,
# or a CLI bug in a PR could fail (or skew) its own gate.
#
# Resolution order:
#   1. HDF_BIN pre-set — local runs, and CI today: the gate-cli job builds
#      from main's tip and passes the path in (see ci.yml for why).
#   2. HDF_CLI_VERSION + HDF_CLI_SHA256 — download that released tarball and
#      verify its checksum. This is the preferred source; CI returns to it
#      once a release ships the effective-status threshold engine (bump the
#      pin via the release skill, Phase 9).

resolve_hdf_bin() {
  if [ -n "${HDF_BIN:-}" ]; then
    return 0
  fi
  : "${HDF_CLI_VERSION:?set HDF_BIN, or HDF_CLI_VERSION+HDF_CLI_SHA256 for a released build}"
  : "${HDF_CLI_SHA256:?set HDF_BIN, or HDF_CLI_VERSION+HDF_CLI_SHA256 for a released build}"
  local tmp
  tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/hdf-cli.tar.gz" \
    "https://github.com/mitre/hdf-libs/releases/download/v${HDF_CLI_VERSION}/hdf_${HDF_CLI_VERSION}_linux_amd64.tar.gz"
  echo "${HDF_CLI_SHA256}  $tmp/hdf-cli.tar.gz" | sha256sum -c -
  tar xzf "$tmp/hdf-cli.tar.gz" -C "$tmp" hdf
  HDF_BIN="$tmp/hdf"
}
