#!/usr/bin/env bash
#
# Pins check-snapshot-archives.sh with throwaway archives: a complete valid
# batch is accepted and listed dependencies-first, and each class of defect the
# publisher must never ship — a stray archive, a missing one, a wrong version,
# a loose sibling pin, a registry in publishConfig, an entry outside package/, a
# symlink member — fails with nothing on stdout.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/check-snapshot-archives.sh"

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

readonly VERSION=3.7.3-next.4100.2

root="$work/root"
mkdir -p "$root/hdf-pear" "$root/hdf-apple" "$root/hdf-cli"
jq -n '{name:"@mitre/hdf-pear", version:"3.7.2"}' > "$root/hdf-pear/package.json"
jq -n '{name:"@mitre/hdf-apple", version:"3.7.2", dependencies:{"@mitre/hdf-pear":"workspace:^"}}' > "$root/hdf-apple/package.json"
jq -n '{name:"@mitre/hdf-cli", version:"3.7.2", private:true}' > "$root/hdf-cli/package.json"

# archive <dir> <pkg> <manifest-json> [extra tar entries created under <dir>/stage]
archive() {
  local dir="$1" pkg="$2" json="$3"
  shift 3
  local stage="$dir/stage-$pkg"
  rm -rf "$stage"
  mkdir -p "$stage/package" "$dir"
  printf '%s\n' "$json" > "$stage/package/package.json"
  printf 'export const ok = true;\n' > "$stage/package/index.js"
  for entry in "$@"; do
    case "$entry" in
      symlink) ln -s index.js "$stage/package/link.js" ;;
      outside) mkdir -p "$stage/other" && printf 'x\n' > "$stage/other/file.js" ;;
    esac
  done
  if [ -d "$stage/other" ]; then
    tar -czf "$dir/mitre-hdf-$pkg-$VERSION.tgz" -C "$stage" package other
  else
    tar -czf "$dir/mitre-hdf-$pkg-$VERSION.tgz" -C "$stage" package
  fi
  rm -rf "$stage"
}

good_pear() { jq -nc --arg v "$VERSION" '{name:"@mitre/hdf-pear", version:$v}'; }
good_apple() { jq -nc --arg v "$VERSION" '{name:"@mitre/hdf-apple", version:$v, dependencies:{"@mitre/hdf-pear":$v, ajv:"^8.17.1"}, publishConfig:{access:"public"}}'; }

# run <label> <want-exit> <dir>; on success also checks stdout is the ordered list
run() {
  local label="$1" want="$2" dir="$3" out rc
  out="$("$SCRIPT" "$dir" "$VERSION" "$root" 2> "$work/stderr")"
  rc=$?
  if [ "$want" -eq 0 ]; then
    if [ "$rc" -eq 0 ] && [ "$out" = $'hdf-pear\nhdf-apple' ]; then
      report "$label" 0
    else
      report "$label" 1 "exit $rc, stdout '$out'"
      sed 's/^/       /' "$work/stderr"
    fi
  elif [ "$rc" -ne 0 ] && [ -z "$out" ]; then
    report "$label" 0
  else
    report "$label" 1 "exit $rc, stdout '$out'"
  fi
}

d="$work/valid"; archive "$d" pear "$(good_pear)"; archive "$d" apple "$(good_apple)"
run "a complete valid batch is accepted and listed dependencies-first" 0 "$d"

d="$work/extra"; archive "$d" pear "$(good_pear)"; archive "$d" apple "$(good_apple)"
cp "$d/mitre-hdf-pear-$VERSION.tgz" "$d/mitre-hdf-stray-$VERSION.tgz"
run "an archive no public package accounts for fails" 1 "$d"

d="$work/missing"; archive "$d" pear "$(good_pear)"
run "a public package without an archive fails" 1 "$d"

d="$work/wrongversion"; archive "$d" pear "$(jq -nc '{name:"@mitre/hdf-pear", version:"3.7.2"}')"; archive "$d" apple "$(good_apple)"
run "a manifest at another version fails" 1 "$d"

d="$work/loosepin"; archive "$d" pear "$(good_pear)"
archive "$d" apple "$(jq -nc --arg v "$VERSION" '{name:"@mitre/hdf-apple", version:$v, dependencies:{"@mitre/hdf-pear":"^3.7.2"}}')"
run "a sibling pin not at the snapshot version fails" 1 "$d"

d="$work/registry"; archive "$d" pear "$(good_pear)"
archive "$d" apple "$(jq -nc --arg v "$VERSION" '{name:"@mitre/hdf-apple", version:$v, dependencies:{"@mitre/hdf-pear":$v}, publishConfig:{access:"public", registry:"https://example.invalid"}}')"
run "a publishConfig beyond public access fails" 1 "$d"

d="$work/wrongname"; archive "$d" pear "$(jq -nc --arg v "$VERSION" '{name:"@mitre/hdf-plum", version:$v}')"; archive "$d" apple "$(good_apple)"
run "a manifest naming another package fails" 1 "$d"

d="$work/outside"; archive "$d" pear "$(good_pear)" outside; archive "$d" apple "$(good_apple)"
run "an entry outside package/ fails" 1 "$d"

d="$work/symlink"; archive "$d" pear "$(good_pear)" symlink; archive "$d" apple "$(good_apple)"
run "a symlink member fails" 1 "$d"

d="$work/linked"; archive "$d" pear "$(good_pear)"; archive "$d" apple "$(good_apple)"
mv "$d/mitre-hdf-pear-$VERSION.tgz" "$d/real.tgz.bak" && ln -s "$d/real.tgz.bak" "$d/mitre-hdf-pear-$VERSION.tgz"
run "an archive that is itself a symlink fails" 1 "$d"

out="$("$SCRIPT" "$work/valid" 3.7.3-rc.1 "$root" 2>/dev/null)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && [ -z "$out" ] || ok=1
report "a non-snapshot version is refused" "$ok" "exit $rc"

out="$("$SCRIPT" "$work/nowhere" "$VERSION" "$root" 2>/dev/null)"
rc=$?
ok=0; [ "$rc" -ne 0 ] && [ -z "$out" ] || ok=1
report "a missing archive directory is refused" "$ok" "exit $rc"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
