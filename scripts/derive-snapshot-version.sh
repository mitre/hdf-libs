#!/usr/bin/env bash
#
# Prints the version a main snapshot of HEAD publishes as:
# <base>-next.<run-id>.<attempt>, where <base> is the release the tree is
# heading for. It is the newest reachable stable tag plus one patch, or plus one
# minor when hdf-schema/src/schemas changed since that tag (the project's bump
# rule), floored at the version hdf-schema/package.json already declares — so a
# merged prepare-release commit, including one for a major no tag yet names,
# never produces a snapshot that sorts below the release it precedes.
#
# Usage: derive-snapshot-version.sh <run-id> <attempt> [<root>]
#
# THIS SCRIPT FAILS CLOSED. No reachable stable tag, an unreadable declared
# version, or a git error while diffing the schema directory each exits nonzero
# rather than guessing a version that a tag then makes permanent.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <run-id> <attempt> [<root>]" >&2
  exit 2
}

[ $# -ge 2 ] || usage
readonly RUN_ID="$1"
readonly ATTEMPT="$2"
if [ $# -ge 3 ]; then
  root="$3"
else
  root="$(git rev-parse --show-toplevel)"
fi

if [[ ! "$RUN_ID" =~ ^[1-9][0-9]*$ ]] || [[ ! "$ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: run id '$RUN_ID' and attempt '$ATTEMPT' must both be positive integers" >&2
  exit 1
fi

cd "$root"

stable=$(git tag --merged HEAD --sort=-version:refname --list 'v*' | awk '/^v[0-9]+\.[0-9]+\.[0-9]+$/ { print; exit }')
if [ -z "$stable" ]; then
  echo "ERROR: no stable v<major>.<minor>.<patch> tag is reachable from HEAD" >&2
  exit 1
fi
IFS=. read -r major minor patch <<< "${stable#v}"

# git diff --quiet exits 1 on a difference and higher on an error; only the
# first two answers may choose a bump.
schema_rc=0
git diff --quiet "$stable" HEAD -- hdf-schema/src/schemas || schema_rc=$?
case "$schema_rc" in
  0) derived="$major.$minor.$((patch + 1))" ;;
  1) derived="$major.$((minor + 1)).0" ;;
  *) echo "ERROR: git diff $stable..HEAD -- hdf-schema/src/schemas failed (exit $schema_rc)" >&2; exit 1 ;;
esac

declared=$(jq -er '.version' hdf-schema/package.json 2>/dev/null) || {
  echo "ERROR: hdf-schema/package.json carries no readable version" >&2
  exit 1
}
declared="${declared%%-*}"
if [[ ! "$declared" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: declared version '$declared' is not <major>.<minor>.<patch>" >&2
  exit 1
fi

base=$(printf '%s\n%s\n' "$derived" "$declared" | sort -t. -k1,1n -k2,2n -k3,3n | tail -n1)
echo "$base-next.$RUN_ID.$ATTEMPT"
