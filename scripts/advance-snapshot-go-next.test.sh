#!/usr/bin/env bash
#
# Pins advance-snapshot-go-next.sh offline against a local bare repository standing in
# for origin: two main commits, prepared children carrying snapshots/v tags, a commit off
# main, and a next branch set per case. Covers the first advance, a forward move, a rerun
# of the same source, an advance to where next already is, refusal to move next back, a
# version with no tag, a tag on another commit, a wrong parent, a source off main, usage.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/advance-snapshot-go-next.sh"

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

readonly ORIGIN="$work/origin.git"
readonly SEED="$work/seed"
git_q() {
  git -C "$SEED" -c user.name=test -c user.email=test@example.com -c commit.gpgsign=false \
    -c tag.gpgsign=false "$@" >/dev/null 2>&1
}
commit_on() { git -C "$SEED" -c user.name=test -c user.email=test@example.com \
  -c commit.gpgsign=false commit-tree "$(git -C "$SEED" rev-parse "$1^{tree}")" -p "$1" -m "$2"; }

git init -q --bare --initial-branch=main "$ORIGIN"
git init -q --initial-branch=main "$SEED"
git_q remote add origin "$ORIGIN"
echo a > "$SEED/file" && git_q add file && git_q commit -m "main a"
A=$(git -C "$SEED" rev-parse HEAD)
echo b > "$SEED/file" && git_q add file && git_q commit -m "main b"
B=$(git -C "$SEED" rev-parse HEAD)
X=$(commit_on "$A" "off main")
PA=$(commit_on "$A" "prepared a")
PA2=$(commit_on "$A" "prepared a again")
PB=$(commit_on "$B" "prepared b")
PBU=$(commit_on "$B" "prepared b, never tagged")
PX=$(commit_on "$X" "prepared off main")

readonly V1=3.8.0-next.101.1 V2=3.8.0-next.102.1 V3=3.8.0-next.103.1
readonly V4=3.8.0-next.104.1 V5=3.8.0-next.105.1
git_q tag -a -m snapshot "snapshots/v$V1" "$PA"
git_q tag -a -m snapshot "snapshots/v$V2" "$PA2"
git_q tag -a -m snapshot "snapshots/v$V3" "$PB"
git_q tag -a -m snapshot "snapshots/v$V4" "$PX"
git_q push origin main "refs/tags/*:refs/tags/*"

set_next() {
  if [ -n "$1" ]; then
    git_q push --force origin "$1:refs/heads/next"
  else
    git_q push origin --delete next || :
  fi
}
origin_next() { git -C "$ORIGIN" rev-parse --verify --quiet refs/heads/next || echo absent; }

run() {
  local name="$1"
  shift
  local d="$work/$name"
  git clone -q "$ORIGIN" "$d/clone" 2>/dev/null
  (cd "$d/clone" && bash "$SCRIPT" "$@") > "$d/stdout" 2> "$d/stderr"
  echo $? > "$d/rc"
}
rc_of() { cat "$work/$1/rc"; }

# Case 1: no next yet; the first snapshot creates it.
set_next ""
run first "$V1" "$A" "$PA"
ok=0; [ "$(rc_of first)" -eq 0 ] && [ "$(origin_next)" = "$PA" ] || ok=1
report "first advance: exit 0 and next is the prepared commit" "$ok" "exit $(rc_of first), next $(origin_next)"
ok=0; grep -qxF $'next\t'"$PA"$'\t'"$V1" "$work/first/stdout" || ok=1
report "first advance: stdout names the commit and version" "$ok"

# Case 2: a newer source moves next forward.
set_next "$PA"
run forward "$V3" "$B" "$PB"
ok=0; [ "$(rc_of forward)" -eq 0 ] && [ "$(origin_next)" = "$PB" ] || ok=1
report "forward: next moves to the newer snapshot" "$ok" "exit $(rc_of forward), next $(origin_next)"

# Case 3: a rerun of the same source under a fresh version moves next.
set_next "$PA"
run rerun "$V2" "$A" "$PA2"
ok=0; [ "$(rc_of rerun)" -eq 0 ] && [ "$(origin_next)" = "$PA2" ] || ok=1
report "rerun of the same source: next moves" "$ok" "exit $(rc_of rerun), next $(origin_next)"

# Case 4: next is already at the snapshot.
set_next "$PB"
run already "$V3" "$B" "$PB"
ok=0; [ "$(rc_of already)" -eq 0 ] && [ "$(origin_next)" = "$PB" ] || ok=1
grep -qxF $'next\t'"$PB"$'\t'"$V3" "$work/already/stdout" || ok=1
report "already there: exit 0, next unchanged, stdout still names it" "$ok"

# Case 5: an older source never takes next back.
set_next "$PB"
run backwards "$V1" "$A" "$PA"
ok=0; [ "$(rc_of backwards)" -eq 1 ] && [ "$(origin_next)" = "$PB" ] || ok=1
report "backwards: exit 1 and next unchanged" "$ok" "exit $(rc_of backwards), next $(origin_next)"
ok=0; grep -qF 'refusing to move next back' "$work/backwards/stderr" || ok=1
report "backwards: stderr says why" "$ok"

# Case 6: the version has no snapshot tag.
set_next "$PA"
run untagged "$V5" "$B" "$PBU"
ok=0; [ "$(rc_of untagged)" -eq 1 ] && [ "$(origin_next)" = "$PA" ] || ok=1
grep -qF "snapshots/v$V5" "$work/untagged/stderr" || ok=1
report "no tag: exit 1, next unchanged, stderr names the tag" "$ok" "exit $(rc_of untagged)"

# Case 7: the version's tag is on a different commit.
set_next "$PA"
run mistagged "$V1" "$A" "$PA2"
ok=0; [ "$(rc_of mistagged)" -eq 1 ] && [ "$(origin_next)" = "$PA" ] || ok=1
grep -qF 'not the prepared commit' "$work/mistagged/stderr" || ok=1
report "tag on another commit: exit 1 and next unchanged" "$ok" "exit $(rc_of mistagged)"

# Case 8: the prepared commit is not a child of the named source.
set_next "$PA"
run parent "$V3" "$A" "$PB"
ok=0; [ "$(rc_of parent)" -eq 1 ] && [ "$(origin_next)" = "$PA" ] || ok=1
grep -qF 'parent' "$work/parent/stderr" || ok=1
report "wrong parent: exit 1 and next unchanged" "$ok" "exit $(rc_of parent)"

# Case 9: a source that is not on main.
set_next ""
run offmain "$V4" "$X" "$PX"
ok=0; [ "$(rc_of offmain)" -eq 1 ] && [ "$(origin_next)" = absent ] || ok=1
grep -qF 'not on main' "$work/offmain/stderr" || ok=1
report "source off main: exit 1 and no next created" "$ok" "exit $(rc_of offmain), next $(origin_next)"

# Case 10: usage errors exit 2 with nothing on stdout and change nothing.
set_next "$PA"
usage_case() {
  local label="$1"
  shift
  local out rc
  out="$(cd "$SEED" && bash "$SCRIPT" "$@" 2> "$work/usage-stderr")"
  rc=$?
  ok=0
  [ "$rc" -eq 2 ] && [ -z "$out" ] && grep -q '^usage:' "$work/usage-stderr" || ok=1
  [ "$(origin_next)" = "$PA" ] || ok=1
  report "usage: $label" "$ok" "exit $rc, stdout '$out'"
}
usage_case "no arguments"
usage_case "two arguments" "$V1" "$A"
usage_case "version without the next suffix" 3.8.0 "$A" "$PA"
usage_case "abbreviated commit" "$V1" "${A:0:12}" "$PA"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
