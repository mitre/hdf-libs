#!/usr/bin/env bash
#
# Pins resolve-gate-cli-snapshot.sh offline against local repositories standing in for a
# gate-source checkout. Covers the happy path, ordering across release, run ID and attempt
# (including a run ID with a leading zero, which must not be read as octal), a tag name
# outside the version shape being ignored, no snapshot tag at all, a prepared commit whose
# parent is off main, a merge commit carrying two parents, lag at and over the threshold,
# a checkout with no main ref, and usage.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below, and in the
# script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/resolve-gate-cli-snapshot.sh"

work="$(mktemp -d)" || { echo "cannot create a temporary directory" >&2; exit 1; }
trap 'rm -rf "$work"' EXIT

passed=0
failed=0

ok() { echo "ok   $1"; passed=$((passed + 1)); }
bad() { echo "FAIL $1"; echo "     $2"; failed=$((failed + 1)); }

# A repository with main, and helpers to add a prepared child carrying a snapshot tag.
new_repo() {
  local dir="$work/$1"
  rm -rf "$dir"; mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.email t@example.com
  git -C "$dir" config user.name T
  echo one > "$dir/f"; git -C "$dir" add f; git -C "$dir" commit -qm one
  printf '%s' "$dir"
}

commit_on() { # dir message
  echo "$2" >> "$1/f"; git -C "$1" add f; git -C "$1" commit -qm "$2"
}

prepare_tag() { # dir version [parent]
  local dir="$1" version="$2" parent="${3:-HEAD}"
  git -C "$dir" checkout -q --detach "$parent"
  echo "$version" > "$dir/version"; git -C "$dir" add version
  git -C "$dir" commit -qm "chore(snapshot): prepare $version"
  git -C "$dir" tag -a "snapshots/v$version" -m "$version"
  git -C "$dir" checkout -q main
}

run() { ( cd "$1" && shift && bash "$SCRIPT" "$@" 2>&1 ); }
field() { printf '%s' "$1" | sed -n "s/^$2=//p"; }

# ── happy path ───────────────────────────────────────────────────────────────
d=$(new_repo happy); prepare_tag "$d" 1.2.3-next.100.1
out=$(run "$d"); rc=$?
if [ $rc -eq 0 ] && [ "$(field "$out" version)" = "1.2.3-next.100.1" ] && [ "$(field "$out" lag)" = "0" ]; then
  ok "resolves the only snapshot, lag 0"
else bad "resolves the only snapshot, lag 0" "rc=$rc out=$out"; fi

# commit printed is the prepared commit, not its parent
if [ "$(field "$out" commit)" = "$(git -C "$d" rev-list -n1 snapshots/v1.2.3-next.100.1)" ]; then
  ok "prints the prepared commit"
else bad "prints the prepared commit" "$out"; fi

# ── ordering ─────────────────────────────────────────────────────────────────
d=$(new_repo order); prepare_tag "$d" 1.2.3-next.100.1; prepare_tag "$d" 1.2.3-next.100.2
prepare_tag "$d" 1.2.3-next.99.9; prepare_tag "$d" 1.2.4-next.1.1
out=$(run "$d")
if [ "$(field "$out" version)" = "1.2.4-next.1.1" ]; then
  ok "release beats run ID and attempt"
else bad "release beats run ID and attempt" "$out"; fi

d=$(new_repo attempt); prepare_tag "$d" 1.2.3-next.100.1; prepare_tag "$d" 1.2.3-next.100.2
out=$(run "$d")
if [ "$(field "$out" version)" = "1.2.3-next.100.2" ]; then
  ok "later attempt of the same run wins"
else bad "later attempt of the same run wins" "$out"; fi

# A leading-zero run ID must compare base ten, not octal: 0000310 > 250.
d=$(new_repo octal); prepare_tag "$d" 1.2.3-next.250.1; prepare_tag "$d" 1.2.3-next.0000310.1
out=$(run "$d")
if [ "$(field "$out" version)" = "1.2.3-next.0000310.1" ]; then
  ok "a leading-zero run ID compares base ten"
else bad "a leading-zero run ID compares base ten" "$out"; fi

# ── selection is shape-bound ─────────────────────────────────────────────────
d=$(new_repo shape); prepare_tag "$d" 1.2.3-next.100.1
git -C "$d" tag -a 'snapshots/v0junk-not-a-version' -m x
out=$(run "$d")
if [ "$(field "$out" version)" = "1.2.3-next.100.1" ]; then
  ok "a tag outside the version shape is ignored"
else bad "a tag outside the version shape is ignored" "$out"; fi

# ── refusals ─────────────────────────────────────────────────────────────────
d=$(new_repo none)
out=$(run "$d"); rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "no snapshots/v tag"; then
  ok "refuses when there is no snapshot tag"
else bad "refuses when there is no snapshot tag" "rc=$rc out=$out"; fi

d=$(new_repo offmain)
git -C "$d" checkout -q -b side
commit_on "$d" side-only
side=$(git -C "$d" rev-parse HEAD)
git -C "$d" checkout -q main
prepare_tag "$d" 1.2.3-next.100.1 "$side"
out=$(run "$d"); rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "is not on main"; then
  ok "refuses a prepared commit whose parent is off main"
else bad "refuses a prepared commit whose parent is off main" "rc=$rc out=$out"; fi

d=$(new_repo twoparents)
# Distinct files per side, so the merge actually produces a merge commit.
git -C "$d" checkout -q -b other
echo other > "$d/other"; git -C "$d" add other; git -C "$d" commit -qm other
git -C "$d" checkout -q main
echo mainside > "$d/mainside"; git -C "$d" add mainside; git -C "$d" commit -qm mainside
git -C "$d" merge -q --no-ff -m merge other
git -C "$d" tag -a 'snapshots/v1.2.3-next.100.1' -m x
out=$(run "$d"); rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "parents"; then
  ok "refuses a tagged commit with two parents"
else bad "refuses a tagged commit with two parents" "rc=$rc out=$out"; fi

d=$(new_repo lag); prepare_tag "$d" 1.2.3-next.100.1
for i in 1 2 3; do commit_on "$d" "after-$i"; done
out=$(run "$d" 3); rc=$?
if [ $rc -eq 0 ] && [ "$(field "$out" lag)" = "3" ]; then
  ok "lag exactly at the threshold passes"
else bad "lag exactly at the threshold passes" "rc=$rc out=$out"; fi
out=$(run "$d" 2); rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "publisher looks stopped"; then
  ok "refuses lag over the threshold"
else bad "refuses lag over the threshold" "rc=$rc out=$out"; fi

d=$(new_repo nomain); prepare_tag "$d" 1.2.3-next.100.1
git -C "$d" branch -m main trunk
out=$(run "$d"); rc=$?
if [ $rc -ne 0 ] && printf '%s' "$out" | grep -q "no main ref"; then
  ok "refuses a checkout with no main ref"
else bad "refuses a checkout with no main ref" "rc=$rc out=$out"; fi

d=$(new_repo usage); prepare_tag "$d" 1.2.3-next.100.1
out=$(run "$d" notanumber); rc=$?
if [ $rc -eq 2 ]; then ok "usage: a non-numeric lag"; else bad "usage: a non-numeric lag" "rc=$rc out=$out"; fi
out=$(run "$d" 1 2); rc=$?
if [ $rc -eq 2 ]; then ok "usage: too many arguments"; else bad "usage: too many arguments" "rc=$rc out=$out"; fi

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
