#!/usr/bin/env bash
#
# Pins list-npm-packages.sh: the one package inventory every publication path
# reads. The cases are the drift it replaces (a dependent published before its
# dependency, a package missing from one path's hand-kept array) and the
# fail-closed cases, because an empty inventory publishing nothing must not read
# as a successful release.

set -uo pipefail

# A git hook exports GIT_DIR and friends, which would aim every git call below,
# and in the script under test, at the real repository instead of the fixture.
# shellcheck disable=SC2086
unset ${!GIT_@}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LISTER="$script_dir/list-npm-packages.sh"

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

# manifest <root> <dir> <json>
manifest() {
  mkdir -p "$1/$2"
  printf '%s\n' "$3" > "$1/$2/package.json"
}

# --- dependencies come before dependents, whatever the directory order -------
ws="$work/workspace"
manifest "$ws" hdf-apple    '{"name":"@mitre/hdf-apple","dependencies":{"@mitre/hdf-pear":"workspace:^","ajv":"^8"}}'
manifest "$ws" hdf-pear     '{"name":"@mitre/hdf-pear"}'
manifest "$ws" hdf-quince   '{"name":"@mitre/hdf-quince","peerDependencies":{"@mitre/hdf-apple":"workspace:^"}}'
manifest "$ws" hdf-fig      '{"name":"@mitre/hdf-fig","optionalDependencies":{"@mitre/hdf-quince":"workspace:^"},"devDependencies":{"@mitre/hdf-pear":"workspace:^"}}'
manifest "$ws" hdf-private  '{"name":"@mitre/hdf-private","private":true}'
manifest "$ws" hdf-foreign  '{"name":"@other/hdf-foreign"}'
manifest "$ws" site         '{"name":"@mitre/hdf-schema-site","private":true}'
out="$("$LISTER" "$ws" 2>&1)"
rc=$?
want=$'hdf-pear\nhdf-apple\nhdf-quince\nhdf-fig'
if [ "$rc" -eq 0 ] && [ "$out" = "$want" ]; then
  report "lists publishable packages dependencies-first and skips private and foreign names" 0
else
  report "lists publishable packages dependencies-first and skips private and foreign names" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /'
fi

# --- a cycle has no publish order; refusing beats guessing -------------------
cyc="$work/cycle"
manifest "$cyc" hdf-left  '{"name":"@mitre/hdf-left","dependencies":{"@mitre/hdf-right":"workspace:^"}}'
manifest "$cyc" hdf-right '{"name":"@mitre/hdf-right","dependencies":{"@mitre/hdf-left":"workspace:^"}}'
out="$("$LISTER" "$cyc" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q 'cycle'; then
  report "a dependency cycle fails and names it" 0
else
  report "a dependency cycle fails and names it" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /'
fi

# --- fail closed: nothing to publish is not a successful inventory ----------
mkdir -p "$work/empty"
out="$("$LISTER" "$work/empty" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] || ok=1
report "a workspace without hdf-*/package.json fails closed" "$ok" "exit $rc"

only_private="$work/only-private"
manifest "$only_private" hdf-private '{"name":"@mitre/hdf-private","private":true}'
out="$("$LISTER" "$only_private" 2>&1)"
rc=$?
ok=0; [ "$rc" -ne 0 ] || ok=1
report "a workspace with only private packages fails closed" "$ok" "exit $rc"

# --- the real workspace: every public package, each after its dependencies ---
repo="$(cd "$script_dir/.." && pwd)"
out="$("$LISTER" "$repo" 2>&1)"
rc=$?
expected="$(for m in "$repo"/hdf-*/package.json; do
  jq -r 'select(.private != true and (.name | startswith("@mitre/hdf-"))) | input_filename' "$m"
done | xargs -n1 dirname | xargs -n1 basename | sort)"
if [ "$rc" -eq 0 ] && [ "$(printf '%s\n' "$out" | sort)" = "$expected" ]; then
  report "the real workspace lists exactly its public packages" 0
else
  report "the real workspace lists exactly its public packages" 1 "exit $rc"
  diff <(printf '%s\n' "$out" | sort) <(printf '%s\n' "$expected") | sed 's/^/       /'
fi

ordered=0
seen=()
while read -r pkg; do
  deps=$(jq -r '[.dependencies, .peerDependencies, .optionalDependencies] | map(. // {} | keys[]) | .[] | select(startswith("@mitre/hdf-")) | sub("^@mitre/"; "")' "$repo/$pkg/package.json")
  for dep in $deps; do
    [ -f "$repo/$dep/package.json" ] || continue
    if ! printf '%s\n' "${seen[@]+"${seen[@]}"}" | grep -qx "$dep"; then
      echo "       $pkg is listed before its dependency $dep"
      ordered=1
    fi
  done
  seen+=("$pkg")
done <<< "$out"
report "the real workspace never lists a package before one it depends on" "$ordered"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
