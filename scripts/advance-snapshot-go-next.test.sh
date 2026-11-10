#!/usr/bin/env bash
#
# Pins advance-snapshot-go-next.sh offline against a local bare repository standing in
# for origin: two main commits, prepared children carrying snapshots/v tags, a commit off
# main, and a next branch set per case. Covers the first advance, a forward move, a rerun
# of the same source, an advance to where next already is, refusal to move next back to an
# older source or to an older snapshot of the same source, a current next with no snapshot
# tag, a version with no tag, a tag on another commit, a wrong parent, a source off main, a
# source behind main's tip with no next to order against, a concurrent move of next before
# the push, a read-back that disagrees, and usage.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/advance-snapshot-go-next.sh"

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
PAU=$(commit_on "$A" "prepared a, never tagged")
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

# Case 1: no next yet; the first snapshot of main's tip creates it.
set_next ""
run first "$V3" "$B" "$PB"
ok=0; [ "$(rc_of first)" -eq 0 ] && [ "$(origin_next)" = "$PB" ] || ok=1
report "first advance: exit 0 and next is the prepared commit" "$ok" "exit $(rc_of first), next $(origin_next)"
ok=0; grep -qxF $'next\t'"$PB"$'\t'"$V3" "$work/first/stdout" || ok=1
report "first advance: stdout names the commit and version" "$ok"

# Case 1a: no next yet and a source behind main's tip. With no branch to order
# against, the tip is the only thing that says this snapshot is the current one.
set_next ""
run first-stale "$V1" "$A" "$PA"
ok=0; [ "$(rc_of first-stale)" -eq 1 ] && [ "$(origin_next)" = absent ] || ok=1
report "first advance from a stale source: exit 1 and next stays absent" "$ok" \
  "exit $(rc_of first-stale), next $(origin_next)"
ok=0; grep -qF 'is not main' "$work/first-stale/stderr" &&
  grep -qF "$A" "$work/first-stale/stderr" && grep -qF "$B" "$work/first-stale/stderr" || ok=1
report "first advance from a stale source: stderr names the source and the tip" "$ok"

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

# Case 5a: an older snapshot of the same source never takes next back. Both prepared
# commits are children of A, so ancestry alone cannot order them; the version does.
set_next "$PA2"
run samesource-back "$V1" "$A" "$PA"
ok=0; [ "$(rc_of samesource-back)" -eq 1 ] && [ "$(origin_next)" = "$PA2" ] || ok=1
report "older snapshot of the same source: exit 1 and next unchanged" "$ok" \
  "exit $(rc_of samesource-back), next $(origin_next)"
ok=0; grep -qF "snapshots/v$V2" "$work/samesource-back/stderr" &&
  grep -qF 'refusing to move next back' "$work/samesource-back/stderr" || ok=1
report "older snapshot of the same source: stderr names the current version" "$ok"

# Case 5b: next on a commit of the same source that carries no snapshot tag cannot be
# ordered against the new version, so it is left alone.
set_next "$PAU"
run current-untagged "$V2" "$A" "$PA2"
ok=0; [ "$(rc_of current-untagged)" -eq 1 ] && [ "$(origin_next)" = "$PAU" ] || ok=1
grep -qF 'no snapshot tag' "$work/current-untagged/stderr" || ok=1
report "current next untagged: exit 1, next unchanged, stderr says why" "$ok" \
  "exit $(rc_of current-untagged), next $(origin_next)"

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

# Case 9a: another writer moves next between the script's read and its push. A git
# wrapper ahead on PATH stands in for that writer; the lease must reject the push and
# keep the other writer's next.
real_git="$(command -v git)"
mkdir -p "$work/lease-bin"
cat > "$work/lease-bin/git" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" = push ]; then
  "$real_git" -C "$ORIGIN" update-ref refs/heads/next "$PA2"
fi
exec "$real_git" "\$@"
EOF
chmod +x "$work/lease-bin/git"
set_next "$PA"
PATH="$work/lease-bin:$PATH" run lease "$V3" "$B" "$PB"
ok=0; [ "$(rc_of lease)" -eq 1 ] && [ "$(origin_next)" = "$PA2" ] || ok=1
grep -qF "pushing next to $PB failed" "$work/lease/stderr" || ok=1
report "concurrent move before the push: exit 1 and the other write stands" "$ok" \
  "exit $(rc_of lease), next $(origin_next)"

# Case 9b: the push is accepted but next reads back as another commit. A post-receive
# hook on origin moves next after the push lands.
set_next "$PA"
printf '#!/bin/sh\ngit update-ref refs/heads/next %s\n' "$PA2" > "$ORIGIN/hooks/post-receive"
chmod +x "$ORIGIN/hooks/post-receive"
run readback "$V3" "$B" "$PB"
rm -f "$ORIGIN/hooks/post-receive"
ok=0; [ "$(rc_of readback)" -eq 1 ] || ok=1
grep -qF "next reads back as $PA2, expected $PB" "$work/readback/stderr" || ok=1
[ ! -s "$work/readback/stdout" ] || ok=1
report "read-back disagrees: exit 1, stderr names both commits, nothing on stdout" "$ok" \
  "exit $(rc_of readback)"

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
usage_case "abbreviated source commit" "$V1" "${A:0:12}" "$PA"
usage_case "abbreviated prepared commit" "$V1" "$A" "${PA:0:12}"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
