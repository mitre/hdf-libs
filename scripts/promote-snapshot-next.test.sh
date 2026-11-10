#!/usr/bin/env bash
#
# Pins promote-snapshot-next.sh offline: a fake npm records every dist-tag add
# and fails the packages a fixture names, a fake curl answers dist-tags from a
# fixture directory and can stay stale for a counted number of calls. Covers
# immediate convergence, convergence on a later poll, a package that never
# converges, an add that fails, usage errors, and the shape of the table.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/promote-snapshot-next.sh"

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

readonly VERSION=3.8.0-next.42548603920.1
readonly OLD=3.8.0-next.1.1
readonly REGISTRY='--registry=https://registry.npmjs.org --@mitre:registry=https://registry.npmjs.org'
packages=(hdf-schema hdf-utilities hdf-mappings hdf-validators hdf-parsers hdf-converters
  hdf-generators hdf-diff hdf-engine hdf-extension-graph hdf-fixtures hdf-openapi)
readonly COUNT="${#packages[@]}"
printf '%s\n' "${packages[@]}" > "$work/packages.txt"

mkdir -p "$work/bin"
cat > "$work/bin/npm" <<'NPM'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
spec="${3:-}"
name="${spec#@mitre/}"
name="${name%@*}"
if [ -f "$FAKE_NPM_FAIL" ] && grep -qxF "$name" "$FAKE_NPM_FAIL"; then
  echo "npm ERR! fake registry refused $spec" >&2
  exit 1
fi
echo "+next: $spec"
NPM
cat > "$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -uo pipefail
url="${!#}"
printf '%s\n' "$url" >> "$FAKE_CURL_LOG"
name="${url#https://registry.npmjs.org/-/package/@mitre%2f}"
name="${name%/dist-tags}"
counter="$FAKE_CURL_DIR/$name.stale"
if [ -f "$counter" ] && [ "$(cat "$counter")" -gt 0 ]; then
  echo "$(( $(cat "$counter") - 1 ))" > "$counter"
  cat "$FAKE_CURL_DIR/$name.stale.json"
elif [ -f "$FAKE_CURL_DIR/$name.json" ]; then
  cat "$FAKE_CURL_DIR/$name.json"
else
  echo '{}'
fi
CURL
chmod +x "$work/bin/npm" "$work/bin/curl"

# fixtures <case>: a dist-tags document at the version for every package
fixtures() {
  local dir="$work/$1/dist-tags" name
  mkdir -p "$dir"
  for name in "${packages[@]}"; do
    jq -n --arg v "$VERSION" '{latest: "3.7.3", next: $v}' > "$dir/$name.json"
  done
  : > "$work/$1/fail.txt"
}

# run <case> <bound> <interval> [args...]: saves stdout, stderr, exit code and the logs
run() {
  local case="$1" bound="$2" interval="$3"
  shift 3
  local dir="$work/$case"
  mkdir -p "$dir/dist-tags"
  : > "$dir/npm.log"
  : > "$dir/curl.log"
  FAKE_NPM_LOG="$dir/npm.log" FAKE_NPM_FAIL="$dir/fail.txt" \
  FAKE_CURL_LOG="$dir/curl.log" FAKE_CURL_DIR="$dir/dist-tags" \
  PATH="$work/bin:$PATH" bash "$SCRIPT" "$@" "$bound" "$interval" \
    > "$dir/stdout" 2> "$dir/stderr"
  echo $? > "$dir/rc"
}

count_matching() { grep -cF -- "$1" "$2" || true; }
url_of() { echo "https://registry.npmjs.org/-/package/@mitre%2f$1/dist-tags"; }

# Case 1: every add succeeds and every package converges on the first poll.
fixtures all
run all 3 1 "$VERSION" "$work/packages.txt"
d="$work/all"
report "all converge: exit 0" "$(cat "$d/rc")" "exit $(cat "$d/rc")"
ok=0
[ "$(count_matching 'dist-tag add' "$d/npm.log")" -eq "$COUNT" ] || ok=1
for name in "${packages[@]}"; do
  grep -qxF "dist-tag add @mitre/$name@$VERSION next $REGISTRY" "$d/npm.log" || ok=1
done
report "all converge: one add per package with the spec and both registry flags" "$ok"
ok=0
[ "$(grep -c $'\tok$' "$d/stdout")" -eq "$COUNT" ] || ok=1
report "all converge: table marks every package ok" "$ok"
ok=0
[ "$(grep -vc '^poll:' "$d/stdout")" -eq "$COUNT" ] || ok=1
grep -q '^+next' "$d/stdout" && ok=1
report "all converge: stdout holds only poll: lines and the table" "$ok"
ok=0
[ "$(count_matching "$(url_of hdf-schema)" "$d/curl.log")" -eq 1 ] || ok=1
report "all converge: a converged package is read back once" "$ok"

# Case 2: one package answers the previous version for two polls, then converges.
fixtures later
echo 2 > "$work/later/dist-tags/hdf-diff.stale"
jq -n --arg v "$OLD" '{latest: "3.7.3", next: $v}' > "$work/later/dist-tags/hdf-diff.stale.json"
run later 3 1 "$VERSION" "$work/packages.txt"
d="$work/later"
report "late convergence: exit 0" "$(cat "$d/rc")" "exit $(cat "$d/rc")"
ok=0
[ "$(count_matching "$(url_of hdf-diff)" "$d/curl.log")" -eq 3 ] || ok=1
report "late convergence: the slow package is asked three times" "$ok" "$(count_matching "$(url_of hdf-diff)" "$d/curl.log")"
ok=0
for name in "${packages[@]}"; do
  [ "$name" = hdf-diff ] && continue
  [ "$(count_matching "$(url_of "$name")" "$d/curl.log")" -eq 1 ] || ok=1
done
report "late convergence: every other package is asked once" "$ok"
ok=0
[ "$(grep -c $'\tok$' "$d/stdout")" -eq "$COUNT" ] || ok=1
report "late convergence: table marks every package ok" "$ok"

# Case 3: one package never leaves the previous version.
fixtures never
jq -n --arg v "$OLD" '{latest: "3.7.3", next: $v}' > "$work/never/dist-tags/hdf-engine.json"
run never 3 1 "$VERSION" "$work/packages.txt"
d="$work/never"
ok=0; [ "$(cat "$d/rc")" -eq 1 ] || ok=1
report "never converges: exit 1" "$ok" "exit $(cat "$d/rc")"
ok=0
grep -qF "hdf-engine: next is $OLD, expected $VERSION" "$d/stderr" || ok=1
report "never converges: stderr names the package with observed and expected" "$ok"
ok=0
grep -qF 'partial promotion: re-run the failed publish job; do not fix next by hand' "$d/stderr" || ok=1
report "never converges: stderr carries the partial promotion line" "$ok"
ok=0
grep -qxF $'hdf-engine\t'"$OLD"$'\tstale' "$d/stdout" || ok=1
[ "$(grep -c $'\tok$' "$d/stdout")" -eq $((COUNT - 1)) ] || ok=1
report "never converges: table marks it stale and the others ok" "$ok"
ok=0
[ "$(count_matching 'dist-tag add' "$d/npm.log")" -eq "$COUNT" ] || ok=1
report "never converges: the add was still issued for every package" "$ok"
ok=0
[ "$(count_matching "$(url_of hdf-engine)" "$d/curl.log")" -ge 3 ] || ok=1
report "never converges: the stale package is polled until the bound" "$ok"

# Case 4: one add fails; the rest are still attempted and the read-back still runs.
fixtures addfail
echo hdf-mappings > "$work/addfail/fail.txt"
run addfail 3 1 "$VERSION" "$work/packages.txt"
d="$work/addfail"
ok=0; [ "$(cat "$d/rc")" -eq 1 ] || ok=1
report "add fails: exit 1" "$ok" "exit $(cat "$d/rc")"
ok=0
[ "$(count_matching 'dist-tag add' "$d/npm.log")" -eq "$COUNT" ] || ok=1
grep -qF "dist-tag add @mitre/hdf-openapi@$VERSION" "$d/npm.log" || ok=1
report "add fails: every later package is still added" "$ok"
ok=0
grep -qF 'dist-tag add failed for: hdf-mappings' "$d/stderr" || ok=1
report "add fails: stderr names the failed package" "$ok"
ok=0
[ "$(wc -l < "$d/curl.log")" -eq "$COUNT" ] || ok=1
[ "$(grep -vc '^poll:' "$d/stdout")" -eq "$COUNT" ] || ok=1
report "add fails: read-back still runs and the table is printed" "$ok"

# Case 5: usage errors exit 2 with nothing on stdout.
usage_case() {
  local label="$1"
  shift
  local out rc
  out="$(PATH="$work/bin:$PATH" bash "$SCRIPT" "$@" 2> "$work/usage-stderr")"
  rc=$?
  ok=0
  [ "$rc" -eq 2 ] && [ -z "$out" ] && grep -q '^usage:' "$work/usage-stderr" || ok=1
  report "usage: $label" "$ok" "exit $rc, stdout '$out'"
}
: > "$work/empty.txt"
usage_case "no arguments"
usage_case "one argument" "$VERSION"
usage_case "non-integer bound" "$VERSION" "$work/packages.txt" soon 1
usage_case "non-integer interval" "$VERSION" "$work/packages.txt" 3 1.5
usage_case "empty packages file" "$VERSION" "$work/empty.txt" 3 1
usage_case "missing packages file" "$VERSION" "$work/nowhere.txt" 3 1
usage_case "too many arguments" "$VERSION" "$work/packages.txt" 3 1 extra

# Case 6: the table keeps the packages-file order and has three tab-separated fields.
d="$work/all"
ok=0
[ "$(grep -v '^poll:' "$d/stdout" | cut -f1)" = "$(cat "$work/packages.txt")" ] || ok=1
report "table: rows follow the packages-file order" "$ok"
ok=0
grep -v '^poll:' "$d/stdout" | awk -F'\t' 'NF != 3 { bad = 1 } END { exit bad }' || ok=1
report "table: every row has exactly three tab-separated fields" "$ok"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
