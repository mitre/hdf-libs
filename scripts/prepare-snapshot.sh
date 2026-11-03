#!/usr/bin/env bash
#
# Builds the commit a main snapshot publishes from: HEAD with the snapshot
# version written into every publishable package manifest (its own version and
# its sibling pins), the hdf-engine version constants, and every intra-repo
# go.mod require. The commit object is created on top of HEAD without moving
# HEAD or any ref; its hash is the only line printed to stdout. The inventory
# the publisher and tagger rely on (packages.txt, gomods.txt, snapshot.json)
# is written to <artifact-dir>.
#
# Usage: prepare-snapshot.sh <version> <artifact-dir> [<root>]
#        version is <major>.<minor>.<patch>-next.<run-id>.<attempt>
#
# THIS SCRIPT FAILS CLOSED. A dirty tree, a version constant it cannot find
# exactly once, a sibling require left behind, or any file changed beyond the
# ones it means to change each exits nonzero before a commit exists.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> <artifact-dir> [<root>]" >&2
  exit 2
}

[ $# -ge 2 ] || usage
readonly VERSION="$1"
artifact="$2"
if [ $# -ge 3 ]; then
  root="$3"
else
  root="$(git rev-parse --show-toplevel)"
fi
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-next\.[1-9][0-9]*\.[1-9][0-9]*$ ]]; then
  echo "ERROR: '$VERSION' is not a snapshot version (<major>.<minor>.<patch>-next.<run-id>.<attempt>)" >&2
  exit 1
fi

cd "$root"
if [ -n "$(git status --porcelain)" ]; then
  echo "ERROR: the working tree is not clean; a snapshot is prepared from HEAD alone" >&2
  exit 1
fi
source=$(git rev-parse HEAD)

# The engine stamps its version into merged documents and MCP handles, and its
# tests pin both constants to hdf-engine/package.json; a snapshot that rewrote
# the manifest alone would report the previous release from inside every
# document it produced. Both are located before anything is rewritten.
ts_constant=hdf-engine/src/version.ts
go_constant=hdf-engine/go/engine.go
test "$(grep -cE "^export const engineVersion = '[^']+';$" "$ts_constant")" -eq 1 || {
  echo "ERROR: $ts_constant does not declare engineVersion exactly once" >&2
  exit 1
}
go_literals=$(awk '
  /^func Version\(\) string \{$/ { inside = 1 }
  inside && /^\treturn "[^"]+"$/ { found++ }
  inside && /^\}$/ { inside = 0 }
  END { print found + 0 }
' "$go_constant")
test "$go_literals" -eq 1 || {
  echo "ERROR: Version() in $go_constant does not return one literal" >&2
  exit 1
}

mkdir -p "$artifact"
artifact="$(cd "$artifact" && pwd)"

# Every intermediate list is a plain command substitution so a helper's failure
# stops the script; a process substitution would hide it from set -e.
packages=$("$script_dir/list-npm-packages.sh" "$root")
changed=()
: > "$artifact/packages.txt"
while read -r pkg; do
  [ -n "$pkg" ] || continue
  manifest="$pkg/package.json"
  rewritten=$(mktemp)
  jq --arg version "$VERSION" '
    .version = $version |
    reduce ["dependencies", "peerDependencies", "optionalDependencies"][] as $field (.;
      if .[$field] then .[$field] |= with_entries(
        if .key | startswith("@mitre/hdf-") then .value = $version else . end
      ) else . end)
  ' "$manifest" > "$rewritten"
  mv "$rewritten" "$manifest"
  changed+=("$manifest")
  echo "$pkg" >> "$artifact/packages.txt"
done <<EOF_PACKAGES
$packages
EOF_PACKAGES
test "${#changed[@]}" -gt 0

rewritten=$(mktemp)
sed -E "s/^(export const engineVersion = ')[^']+(';)$/\1$VERSION\2/" "$ts_constant" > "$rewritten"
mv "$rewritten" "$ts_constant"
grep -qxF "export const engineVersion = '$VERSION';" "$ts_constant"

rewritten=$(mktemp)
awk -v version="$VERSION" '
  /^func Version\(\) string \{$/ { inside = 1 }
  inside && /^\treturn "[^"]+"$/ { $0 = "\treturn \"" version "\"" }
  inside && /^\}$/ { inside = 0 }
  { print }
' "$go_constant" > "$rewritten"
mv "$rewritten" "$go_constant"
grep -qxF "	return \"$VERSION\"" "$go_constant"
changed+=("$ts_constant" "$go_constant")

bash "$script_dir/set-go-module-versions.sh" "v$VERSION" "$root" >&2
git ls-files '**/go.mod' > "$artifact/gomods.txt"
test -s "$artifact/gomods.txt"
while read -r gomod; do changed+=("$gomod"); done < "$artifact/gomods.txt"

git add -- "${changed[@]}"
# Anything modified beyond the files added above means a helper reached further
# than it claims, and the commit would carry it.
stray=$(git status --porcelain | grep -v '^M  ' || true)
if [ -n "$stray" ]; then
  echo "ERROR: unexpected changes outside the snapshot rewrite:" >&2
  printf '%s\n' "$stray" >&2
  exit 1
fi

prepared=$(git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
  commit-tree "$(git write-tree)" -p "$source" -m "chore(snapshot): prepare $VERSION" -m "Snapshot-Source: $source")
jq -n --arg source "$source" --arg prepared "$prepared" --arg version "$VERSION" \
  '{source: $source, prepared: $prepared, version: $version}' > "$artifact/snapshot.json"
echo "$prepared"
