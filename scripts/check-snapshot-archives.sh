#!/usr/bin/env bash
#
# Validates a batch of packed snapshot archives against the trusted source
# checkout before anything is published, and prints the package directories it
# accepted, dependencies first, for the publish loop. Every public package must
# have exactly one archive and nothing else may be present; each archive must
# hold one regular package manifest under package/, no other entry types, no
# path that escapes package/, the exact snapshot name and version, sibling pins
# at that same version, and no publication configuration beyond public access.
#
# Usage: check-snapshot-archives.sh <archives-dir> <version> [<root>]
#
# THIS SCRIPT FAILS CLOSED: the first archive that fails any check exits nonzero
# with nothing printed to stdout, so a publish loop reading it publishes nothing.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <archives-dir> <version> [<root>]" >&2
  exit 2
}

[ $# -ge 2 ] || usage
archives="$1"
readonly VERSION="$2"
if [ $# -ge 3 ]; then
  root="$3"
else
  root="$(git rev-parse --show-toplevel)"
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-next\.[1-9][0-9]*\.[1-9][0-9]*$ ]]; then
  echo "ERROR: '$VERSION' is not a snapshot version" >&2
  exit 1
fi
if [ ! -d "$archives" ]; then
  echo "ERROR: $archives is not a directory" >&2
  exit 1
fi
archives="$(cd "$archives" && pwd)"

packages=$("$script_dir/list-npm-packages.sh" "$root")
cd "$root"
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

accepted=()
while read -r pkg; do
  [ -n "$pkg" ] || continue
  manifest="$pkg/package.json"
  jq -e --arg name "@mitre/$pkg" '.name == $name' "$manifest" >/dev/null ||
    fail "$manifest does not declare @mitre/$pkg"
  archive="$archives/mitre-$pkg-$VERSION.tgz"
  { [ -f "$archive" ] && [ ! -L "$archive" ]; } || fail "$archive is missing or not a regular file"

  tar -tzf "$archive" > "$scratch/members.txt"
  awk '
    $0 !~ /^package(\/|$)/ || /\\/ || /\/\// || /(^|\/)\.\.?($|\/)/ { bad = 1 }
    $0 == "package/package.json" { manifests++ }
    END { exit (bad || manifests != 1) }
  ' "$scratch/members.txt" || fail "$archive has an entry outside package/ or not exactly one package/package.json"

  tar -tvzf "$archive" > "$scratch/member-types.txt"
  awk 'substr($0, 1, 1) !~ /^[-d]$/ { bad = 1 } END { exit bad }' "$scratch/member-types.txt" ||
    fail "$archive contains an entry that is neither a regular file nor a directory"

  tar -xOzf "$archive" package/package.json | jq -es --arg name "@mitre/$pkg" --arg version "$VERSION" '
    length == 1 and (.[0] |
      .name == $name and .version == $version and
      ((.publishConfig // {}) | . == {} or . == {access: "public"}) and
      ([.dependencies, .optionalDependencies, .peerDependencies] |
        all(.[]; (. // {} | to_entries |
          all(.[]; (.key | startswith("@mitre/hdf-") | not) or .value == $version))))
    )
  ' >/dev/null || fail "$archive's manifest is not @mitre/$pkg@$VERSION with sibling pins at $VERSION and public-only publishConfig"
  accepted+=("$pkg")
done <<EOF_PACKAGES
$packages
EOF_PACKAGES

test "${#accepted[@]}" -gt 0 || fail "no package accepted"
shopt -s nullglob
present=("$archives"/*.tgz)
test "${#present[@]}" -eq "${#accepted[@]}" ||
  fail "$archives holds ${#present[@]} archives but ${#accepted[@]} public packages were expected"

printf '%s\n' "${accepted[@]}"
