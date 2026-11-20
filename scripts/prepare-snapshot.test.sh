#!/usr/bin/env bash
#
# Pins prepare-snapshot.sh with a throwaway workspace: every version-bearing
# file the snapshot commit must carry (manifests, sibling pins, both engine
# constants, go.mod requires), the inventory it writes for the publisher and
# tagger, and the fail-closed cases. The real workspace is never touched; `go
# mod edit` needs no network.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/prepare-snapshot.sh"

for tool in git jq go; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is not on PATH" >&2; exit 1; }
done

work="$(mktemp -d)" || { echo "cannot create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

report() {
  local label="$1" ok="$2" detail="${3:-}"
  if [ "$ok" -eq 0 ]; then
    echo "ok   $label"
    pass=$((pass + 1))
  else
    echo "FAIL $label${detail:+ — $detail}"
    fail=$((fail + 1))
  fi
}

git_q() { git -C "$repo" -c user.name=test -c user.email=test@example.com -c commit.gpgsign=false "$@" >/dev/null 2>&1; }

# A workspace with two public packages (one depending on the other), a private
# one, the engine constants, and two Go modules pinned to each other.
make_workspace() {
  repo="$1"
  mkdir -p "$repo/hdf-pear" "$repo/hdf-apple" "$repo/hdf-cli" "$repo/hdf-engine/src" "$repo/hdf-engine/go"
  jq -n '{name:"@mitre/hdf-pear", version:"3.7.2"}' > "$repo/hdf-pear/package.json"
  jq -n '{name:"@mitre/hdf-apple", version:"3.7.2", dependencies:{"@mitre/hdf-pear":"workspace:^", ajv:"^8.17.1"}, peerDependencies:{"@mitre/hdf-engine":"workspace:^"}}' > "$repo/hdf-apple/package.json"
  jq -n '{name:"@mitre/hdf-cli", version:"3.7.2", private:true, dependencies:{"@mitre/hdf-pear":"workspace:^"}}' > "$repo/hdf-cli/package.json"
  jq -n '{name:"@mitre/hdf-engine", version:"3.7.2"}' > "$repo/hdf-engine/package.json"
  cat > "$repo/hdf-engine/src/version.ts" <<'TS'
// Library version, kept on the workspace lockstep with package.json.
export const engineVersion = '3.7.2';
TS
  cat > "$repo/hdf-engine/go/engine.go" <<'GO'
package hdfengine

// Version reports the library version.
func Version() string {
	return "3.7.2"
}

func other() string {
	return "untouched"
}
GO
  cat > "$repo/hdf-engine/go/go.mod" <<'MOD'
module github.com/mitre/hdf-libs/hdf-engine/go/v3

go 1.26.6

require github.com/mitre/hdf-libs/hdf-pear/v3 v3.7.2
MOD
  cat > "$repo/hdf-pear/go.mod" <<'MOD'
module github.com/mitre/hdf-libs/hdf-pear/v3

go 1.26.6
MOD
  git_q init -q -b main
  git_q add -A && git_q commit -m "init"
}

readonly VERSION=3.7.3-next.4100.2

make_workspace "$work/repo"
head_before=$(git -C "$repo" rev-parse HEAD)
prepared="$("$SCRIPT" "$VERSION" "$work/artifact" "$repo" 2> "$work/stderr")"
rc=$?
if [ "$rc" -eq 0 ] && [[ "$prepared" =~ ^[0-9a-f]{40}$ ]]; then
  report "prints the prepared commit and nothing else on stdout" 0
else
  report "prints the prepared commit and nothing else on stdout" 1 "exit $rc, stdout '$prepared'"
  sed 's/^/       /' "$work/stderr"
  echo "cannot continue without a prepared commit"
  exit 1
fi

show() { git -C "$repo" show "$prepared:$1"; }

ok=0; [ "$(git -C "$repo" rev-parse HEAD)" = "$head_before" ] && [ "$(git -C "$repo" show -s --format=%P "$prepared")" = "$head_before" ] || ok=1
report "the commit sits on HEAD and HEAD itself does not move" "$ok"

ok=0; [ "$(git -C "$repo" for-each-ref --format='%(objectname)' | grep -c "$prepared")" -eq 0 ] || ok=1
report "no ref is created for the prepared commit" "$ok"

ok=0; [ "$(show hdf-pear/package.json | jq -r .version)" = "$VERSION" ] &&
  [ "$(show hdf-apple/package.json | jq -r .version)" = "$VERSION" ] &&
  [ "$(show hdf-engine/package.json | jq -r .version)" = "$VERSION" ] || ok=1
report "every public manifest carries the snapshot version" "$ok"

ok=0; [ "$(show hdf-apple/package.json | jq -r '.dependencies["@mitre/hdf-pear"]')" = "$VERSION" ] &&
  [ "$(show hdf-apple/package.json | jq -r '.peerDependencies["@mitre/hdf-engine"]')" = "$VERSION" ] &&
  [ "$(show hdf-apple/package.json | jq -r '.dependencies.ajv')" = "^8.17.1" ] || ok=1
report "sibling pins take the snapshot version and external ranges stay" "$ok"

ok=0; [ "$(show hdf-cli/package.json | jq -r .version)" = "3.7.2" ] || ok=1
report "a private package is left alone" "$ok"

ok=0; show hdf-engine/src/version.ts | grep -qxF "export const engineVersion = '$VERSION';" &&
  [ "$(show hdf-engine/src/version.ts | wc -l | tr -d ' ')" -eq 2 ] || ok=1
report "the TypeScript engine constant is stamped in place" "$ok"

ok=0; show hdf-engine/go/engine.go | grep -qxF "	return \"$VERSION\"" &&
  show hdf-engine/go/engine.go | grep -qxF '	return "untouched"' || ok=1
report "the Go engine constant is stamped and other literals are untouched" "$ok"

ok=0; show hdf-engine/go/go.mod | grep -qF "github.com/mitre/hdf-libs/hdf-pear/v3 v$VERSION" || ok=1
report "intra-repo go.mod requires name the snapshot version" "$ok"

ok=0; [ "$(cat "$work/artifact/packages.txt")" = $'hdf-engine\nhdf-pear\nhdf-apple' ] || ok=1
report "packages.txt lists the public packages dependencies-first" "$ok" "got: $(tr '\n' ' ' < "$work/artifact/packages.txt")"

ok=0; [ "$(sort "$work/artifact/gomods.txt" | tr '\n' ' ')" = "hdf-engine/go/go.mod hdf-pear/go.mod " ] || ok=1
report "gomods.txt lists every tracked go.mod" "$ok" "got: $(tr '\n' ' ' < "$work/artifact/gomods.txt")"

ok=0; [ "$(jq -r '[.source, .prepared, .version] | join(" ")' "$work/artifact/snapshot.json")" = "$head_before $prepared $VERSION" ] || ok=1
report "snapshot.json records source, prepared commit and version" "$ok"

# --- fail closed --------------------------------------------------------------
make_workspace "$work/badversion"
out="$("$SCRIPT" 3.7.3-rc.1 "$work/artifact-bad" "$repo" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && [ ! -e "$work/artifact-bad" ] && [ -z "$(git -C "$repo" status --porcelain)" ] || ok=1
report "a non-snapshot version is refused before anything is written" "$ok" "exit $rc"

make_workspace "$work/dirty"
echo 'scratch' > "$repo/README.md"
out="$("$SCRIPT" "$VERSION" "$work/artifact-dirty" "$repo" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'not clean' || ok=1
report "a dirty working tree is refused" "$ok" "exit $rc"

make_workspace "$work/noconst"
printf 'export const engineVersion = computeIt();\n' > "$repo/hdf-engine/src/version.ts"
git_q add -A && git_q commit -m "hide the constant"
out="$("$SCRIPT" "$VERSION" "$work/artifact-noconst" "$repo" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'engineVersion' || ok=1
report "a TypeScript constant it cannot find fails closed" "$ok" "exit $rc"
ok=0; [ -z "$(git -C "$repo" status --porcelain)" ] || ok=1
report "a TypeScript constant it cannot find leaves the tree untouched" "$ok"

make_workspace "$work/nogoconst"
sed -i.bak 's/^\treturn "3.7.2"$/\treturn version()/' "$repo/hdf-engine/go/engine.go" && rm "$repo/hdf-engine/go/engine.go.bak"
git_q add -A && git_q commit -m "hide the constant"
out="$("$SCRIPT" "$VERSION" "$work/artifact-nogoconst" "$repo" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'Version()' || ok=1
report "a Go constant it cannot find fails closed" "$ok" "exit $rc"
ok=0; [ -z "$(git -C "$repo" status --porcelain)" ] || ok=1
report "a Go constant it cannot find leaves the tree untouched" "$ok"

make_workspace "$work/unpinnable"
cat > "$repo/hdf-pear/go.mod" <<'MOD'
module github.com/mitre/hdf-libs/hdf-pear/v3

go 1.26.6

require github.com/mitre/hdf-libs/brand-new v0.0.0-00010101000000-000000000000
MOD
git_q add -A && git_q commit -m "unpinnable require"
out="$("$SCRIPT" "$VERSION" "$work/artifact-unpinnable" "$repo" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] || ok=1
report "a go.mod require the version cannot be written into fails closed" "$ok" "exit $rc"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
