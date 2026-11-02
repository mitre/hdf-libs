#!/usr/bin/env bash
#
# Pins derive-snapshot-version.sh with a throwaway repository: the patch/minor
# choice, the declared-version floor that keeps a snapshot from sorting below a
# merged prepare-release commit, numeric (not lexical) tag ordering, and the
# fail-closed cases. Never touches this repo and never needs the network.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/derive-snapshot-version.sh"

work="$(mktemp -d)"
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

# declare <version> writes hdf-schema/package.json and commits it.
declare_version() {
  mkdir -p "$repo/hdf-schema"
  jq -n --arg v "$1" '{name:"@mitre/hdf-schema", version:$v}' > "$repo/hdf-schema/package.json"
  git_q add hdf-schema/package.json && git_q commit -m "declare $1"
}

# expect <label> <want-version-or-empty> <want-exit> <args...>
expect() {
  local label="$1" want="$2" want_rc="$3"
  shift 3
  local out rc
  out="$("$SCRIPT" "$@" "$repo" 2>&1)"
  rc=$?
  if [ "$rc" -eq "$want_rc" ] && { [ -z "$want" ] || [ "$out" = "$want" ]; }; then
    report "$label" 0
  else
    report "$label" 1 "wanted exit $want_rc${want:+ and $want}, got exit $rc"
    printf '%s\n' "$out" | sed 's/^/       /'
  fi
}

repo="$work/repo"
mkdir -p "$repo/hdf-schema/src/schemas"
git_q init -q -b main
echo '{"$id":"one"}' > "$repo/hdf-schema/src/schemas/one.schema.json"
echo 'notes' > "$repo/README.md"
git_q add -A && git_q commit -m "init"
declare_version 3.7.2
git_q tag v3.7.2
git_q tag v3.7.2-rc.1
git_q tag v3.6.0

expect "an unchanged tree after the stable tag is the next patch" "3.7.3-next.41.1" 0 41 1

echo 'more notes' >> "$repo/README.md"
git_q add README.md && git_q commit -m "docs"
expect "a change outside the schema directory stays a patch" "3.7.3-next.41.2" 0 41 2

echo '{"$id":"one","title":"x"}' > "$repo/hdf-schema/src/schemas/one.schema.json"
git_q add -A && git_q commit -m "schema"
expect "a schema change is the next minor" "3.8.0-next.42.1" 0 42 1

declare_version 3.8.0-rc.1
expect "a merged rc prepare commit keeps the minor it names" "3.8.0-next.43.1" 0 43 1

declare_version 4.0.0
expect "a merged major prepare commit floors the snapshot at that major" "4.0.0-next.44.1" 0 44 1

git_q tag v4.0.0
declare_version 4.0.0
expect "after the major is tagged the snapshot moves past it" "4.0.1-next.45.1" 0 45 1

# Tags sort as versions: v4.10.0 is newer than v4.9.0 even though "1" < "9".
git_q tag v4.9.0
git_q tag v4.10.0
declare_version 4.10.0
expect "the newest stable tag is chosen numerically" "4.10.1-next.46.1" 0 46 1

echo '{"$id":"two"}' > "$repo/hdf-schema/src/schemas/two.schema.json"
git_q add -A && git_q commit -m "schema again"
expect "a minor bump never rolls into a major" "4.11.0-next.47.1" 0 47 1

expect "a zero run id fails closed" "" 1 0 1
expect "a non-numeric attempt fails closed" "" 1 47 one
out="$("$SCRIPT" 47 2>&1)"
rc=$?
ok=0; [ "$rc" -eq 2 ] || ok=1
report "a missing attempt is a usage error" "$ok" "exit $rc"

jq -n '{name:"@mitre/hdf-schema"}' > "$repo/hdf-schema/package.json"
git_q add -A && git_q commit -m "drop version"
expect "a manifest without a version fails closed" "" 1 48 1

untagged="$work/untagged"
mkdir -p "$untagged/hdf-schema/src/schemas"
repo="$untagged"
git_q init -q -b main
declare_version 3.7.2
git_q tag v3.7.2-rc.1
expect "a tree with only pre-release tags fails closed" "" 1 49 1

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
