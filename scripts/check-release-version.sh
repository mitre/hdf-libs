#!/usr/bin/env bash
#
# Fails if goreleaser built a version other than the tag that triggered the run.
#
# Usage: check-release-version.sh <path-to-goreleaser-metadata.json>
#        (reads the tag from GITHUB_REF_NAME)
#
# v3.7.0 shipped assets named 3.7.0-rc.1: goreleaser derives its version from
# `git describe`, which is ambiguous when a stable tag and its rc sit on one
# commit. GORELEASER_CURRENT_TAG now pins the choice — this asserts the result,
# so removing the pin, a goreleaser precedence change, or a tag/ref mismatch
# fails the build instead of publishing mislabeled assets.
#
# dist/metadata.json is goreleaser's own answer for the version it built, which
# is why it is read instead of the archive filenames: the name template can
# change, the metadata field is the decision itself.
#
# THIS SCRIPT FAILS CLOSED. A metadata.json that is missing, unparseable, or
# carries no .version proves nothing, and must not read as agreement.

set -uo pipefail

metadata="${1:-}"
if [ -z "$metadata" ]; then
  echo "::error::usage: check-release-version.sh <path-to-metadata.json>"
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "::error::jq is not on PATH; cannot read $metadata"
  exit 1
fi

tag="${GITHUB_REF_NAME:-}"
if [ -z "$tag" ]; then
  echo "::error::GITHUB_REF_NAME is unset; there is no triggering tag to compare against"
  exit 1
fi
expected="${tag#v}"

if [ ! -s "$metadata" ]; then
  echo "::error::$metadata is missing or empty; cannot confirm the built version is $expected"
  exit 1
fi

built="$(jq -er '.version' "$metadata" 2>/dev/null)"
if [ -z "$built" ]; then
  echo "::error::$metadata carries no .version; cannot confirm the built version is $expected"
  exit 1
fi

if [ "$built" != "$expected" ]; then
  echo "::error::goreleaser built version $built but the triggering tag is $tag (expected $expected). Assets would ship mislabeled; nothing is published."
  exit 1
fi

echo "built version $built matches the triggering tag $tag"
