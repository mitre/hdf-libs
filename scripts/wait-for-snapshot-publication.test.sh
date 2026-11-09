#!/usr/bin/env bash
#
# Pins wait-for-snapshot-publication.sh offline, with a fake curl on PATH: a
# snapshot served at once passes with every registry URL asked once and before
# any proxy URL; an unserved package times out without the proxy ever being
# asked; an unserved module times out naming its path; a package served on the
# second poll is asked twice; an uppercase module path is refused up front; and
# bad arguments are usage errors.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/wait-for-snapshot-publication.sh"

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

readonly VERSION=3.8.0-next.4100.2
readonly REGISTRY=https://registry.npmjs.org/
readonly PROXY=https://proxy.golang.org/

npm_url() { printf '%s@mitre%%2f%s/%s' "$REGISTRY" "$1" "$VERSION"; }
go_url() { printf '%s%s/@v/v%s.info' "$PROXY" "$1" "$VERSION"; }

# The fake curl appends its argv to $FAKE_CURL_LOG and answers from
# $FAKE_CURL_ANSWERS/<url with every character outside [A-Za-z0-9._-] as _>:
# one HTTP code per line, each ask consuming a line until the last, which
# repeats; a URL without a fixture answers 404.
mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
url=""
for arg in "$@"; do
  case "$arg" in http*) url="$arg" ;; esac
done
printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
fixture="$FAKE_CURL_ANSWERS/$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
code=404
if [ -f "$fixture" ]; then
  code="$(head -n 1 "$fixture")"
  if [ "$(grep -c . "$fixture")" -gt 1 ]; then
    tail -n +2 "$fixture" > "$fixture.next" && mv "$fixture.next" "$fixture"
  fi
fi
printf '%s' "$code"
CURL
chmod +x "$work/bin/curl"

# answer <url> <code>...: the fake's fixture for one URL, in the current case
answer() {
  local url="$1"
  shift
  printf '%s\n' "$@" > "$answers/$(printf '%s' "$url" | tr -c 'A-Za-z0-9._-' '_')"
}

repo="$work/repo"
mkdir -p "$repo/hdf-cli" "$repo/hdf-schema" "$repo/hdf-upper"
printf 'module github.com/mitre/hdf-libs/hdf-cli\n\ngo 1.24\n' > "$repo/hdf-cli/go.mod"
printf 'module github.com/mitre/hdf-libs/hdf-schema\n\ngo 1.24\n' > "$repo/hdf-schema/go.mod"
printf 'module github.com/mitre/hdf-libs/HdfUpper\n\ngo 1.24\n' > "$repo/hdf-upper/go.mod"
printf 'hdf-a\nhdf-b\nhdf-c\n' > "$repo/packages.txt"
printf 'hdf-cli/go.mod\nhdf-schema/go.mod\n' > "$repo/gomods.txt"
printf 'hdf-cli/go.mod\nhdf-upper/go.mod\n' > "$repo/gomods-upper.txt"
: > "$repo/empty.txt"

readonly CLI=github.com/mitre/hdf-libs/hdf-cli
readonly SCHEMA=github.com/mitre/hdf-libs/hdf-schema

# begin <case>: a fresh answers directory and curl log for the case
begin() {
  answers="$work/$1/answers"
  log="$work/$1/curl.log"
  out="$work/$1/stdout"
  err="$work/$1/stderr"
  mkdir -p "$answers"
}

# run <args...>: the script from the fixture repo, through the fake curl; sets rc
run() {
  (cd "$repo" && FAKE_CURL_LOG="$log" FAKE_CURL_ANSWERS="$answers" PATH="$work/bin:$PATH" \
    "$BASH" "$SCRIPT" "$@" > "$out" 2> "$err")
  rc=$?
}

# line_of <first|last> <fixed-string>: that match's line number in the curl log
line_of() {
  local which="$1" text="$2"
  if [ "$which" = first ]; then
    grep -nF "$text" "$log" | head -n 1 | cut -d: -f1
  else
    grep -nF "$text" "$log" | tail -n 1 | cut -d: -f1
  fi
}

# asked <fixed-string>: how many curl invocations carried it; 0 when none ran
asked() {
  if [ -f "$log" ]; then grep -cF "$1" "$log" || true; else echo 0; fi
}

# exit_is <rc> <want>: 0 when they agree, for report
exit_is() {
  if [ "$1" -eq "$2" ]; then echo 0; else echo 1; fi
}

# timeout_message <bound> <still-waiting>: the four-part failure is on stderr, verbatim
timeout_message() {
  local bound="$1" waiting="$2" ok=0
  grep -qF "$VERSION: not every artifact was served within ${bound}s" "$err" || ok=1
  grep -qF "  published: the versions on the registry are immutable and stay published" "$err" || ok=1
  grep -qF "  not run: the consumer install checks did not run" "$err" || ok=1
  grep -qF "  not advanced: next was not moved for any package" "$err" || ok=1
  grep -qF "  recover: re-run the failed publish job once the registry and proxy serve the versions (still waiting: $waiting)" "$err" || ok=1
  return "$ok"
}

# --- 1. everything served at once -------------------------------------------

begin served
for pkg in hdf-a hdf-b hdf-c; do answer "$(npm_url "$pkg")" 200; done
answer "$(go_url "$CLI")" 200
answer "$(go_url "$SCHEMA")" 200
run "$VERSION" packages.txt gomods.txt 2 1
report "all served: exits 0" "$(exit_is "$rc" 0)" "exit $rc: $(cat "$err")"
ok=0; grep -qF "served: 3 npm packages and 2 Go modules at $VERSION after " "$out" || ok=1
report "all served: prints the success line" "$ok" "$(cat "$out")"
ok=0; grep -qF "npm 3/3 served" "$out" && grep -qF "go 2/2 served" "$out" || ok=1
report "all served: reports each phase complete" "$ok" "$(cat "$out")"
ok=0; [ "$(line_of last "$REGISTRY")" -lt "$(line_of first "$PROXY")" ] || ok=1
report "all served: every registry URL is asked before any proxy URL" "$ok"
ok=0
for pkg in hdf-a hdf-b hdf-c; do [ "$(asked "$(npm_url "$pkg")")" -eq 1 ] || ok=1; done
report "all served: each registry URL is asked exactly once" "$ok" "$(cat "$log")"
ok=0; grep -qF -- '--max-time 30' "$log" || ok=1
report "curl is invoked with --max-time" "$ok" "$(head -n 1 "$log")"
ok=0; grep -qF -- "--silent --output /dev/null --write-out %{http_code} --max-time 30 $(npm_url hdf-a)" "$log" || ok=1
report "curl is invoked with the contracted argv" "$ok" "$(head -n 1 "$log")"

# --- 2. a package never served: the proxy is never asked --------------------

begin npm-missing
answer "$(npm_url hdf-a)" 200
answer "$(npm_url hdf-c)" 200
answer "$(go_url "$CLI")" 200
answer "$(go_url "$SCHEMA")" 200
run "$VERSION" packages.txt gomods.txt 2 1
report "unserved package: exits 1" "$(exit_is "$rc" 1)" "exit $rc"
ok=0; timeout_message 2 "@mitre/hdf-b $CLI $SCHEMA" || ok=1
report "unserved package: the four-part message names it" "$ok" "$(cat "$err")"
ok=0; grep -qF "npm 2/3 served, 1 waiting: hdf-b" "$out" || ok=1
report "unserved package: progress names the waiting package" "$ok" "$(cat "$out")"
ok=0; [ "$(asked "$PROXY")" -eq 0 ] || ok=1
report "unserved package: no proxy URL is asked" "$ok" "$(grep -F "$PROXY" "$log")"
ok=0; [ "$(asked "$(npm_url hdf-b)")" -ge 2 ] && [ "$(asked "$(npm_url hdf-a)")" -eq 1 ] || ok=1
report "unserved package: only the waiting package is asked again" "$ok" "$(cat "$log")"
ok=0; [ ! -s "$out" ] || ! grep -qF "served: " "$out" || ok=1
report "unserved package: no success line" "$ok" "$(cat "$out")"

# --- 3. a module never served ------------------------------------------------

begin go-missing
for pkg in hdf-a hdf-b hdf-c; do answer "$(npm_url "$pkg")" 200; done
answer "$(go_url "$CLI")" 200
run "$VERSION" packages.txt gomods.txt 2 1
report "unserved module: exits 1" "$(exit_is "$rc" 1)" "exit $rc"
ok=0; timeout_message 2 "$SCHEMA" || ok=1
report "unserved module: the four-part message names its path" "$ok" "$(cat "$err")"
ok=0; [ "$(asked "$(go_url "$CLI")")" -eq 1 ] && [ "$(asked "$(go_url "$SCHEMA")")" -ge 2 ] || ok=1
report "unserved module: proxy URLs are asked, the served one once" "$ok" "$(cat "$log")"
ok=0; grep -qF "go 1/2 served, 1 waiting: $SCHEMA" "$out" || ok=1
report "unserved module: progress names the waiting module" "$ok" "$(cat "$out")"

# --- 4. served on the second poll --------------------------------------------

begin second-poll
answer "$(npm_url hdf-a)" 200
answer "$(npm_url hdf-b)" 404 200
answer "$(npm_url hdf-c)" 200
answer "$(go_url "$CLI")" 000 200
answer "$(go_url "$SCHEMA")" 200
run "$VERSION" packages.txt gomods.txt 3 1
report "second poll: exits 0" "$(exit_is "$rc" 0)" "exit $rc: $(cat "$err")"
ok=0; [ "$(asked "$(npm_url hdf-b)")" -eq 2 ] && [ "$(asked "$(npm_url hdf-a)")" -eq 1 ] || ok=1
report "second poll: the late package is asked twice, the others once" "$ok" "$(cat "$log")"
ok=0; [ "$(asked "$(go_url "$CLI")")" -eq 2 ] || ok=1
report "second poll: a curl failure (000) is retried" "$ok" "$(cat "$log")"
ok=0; grep -qF "served: 3 npm packages and 2 Go modules at $VERSION after " "$out" || ok=1
report "second poll: prints the success line" "$ok" "$(cat "$out")"

# --- 5. an uppercase module path ----------------------------------------------

begin uppercase
for pkg in hdf-a hdf-b hdf-c; do answer "$(npm_url "$pkg")" 200; done
answer "$(go_url "$CLI")" 200
run "$VERSION" packages.txt gomods-upper.txt 2 1
report "uppercase module path: exits 1" "$(exit_is "$rc" 1)" "exit $rc"
ok=0; grep -qF "github.com/mitre/hdf-libs/HdfUpper" "$err" && grep -qiF "case escaping" "$err" || ok=1
report "uppercase module path: the message names the path" "$ok" "$(cat "$err")"
ok=0; [ "$(asked "$PROXY")" -eq 0 ] || ok=1
report "uppercase module path: no proxy URL is asked" "$ok"

# --- 6. usage errors ------------------------------------------------------------

usage_case() {
  local label="$1"
  shift
  begin "usage-$pass-$fail"
  run "$@"
  ok=0; [ "$rc" -eq 2 ] && grep -qF "usage:" "$err" || ok=1
  report "usage: $label exits 2 with a usage line" "$ok" "exit $rc: $(cat "$err")"
  ok=0; [ ! -f "$log" ] || ok=1
  report "usage: $label asks nothing" "$ok"
}

usage_case "no arguments"
usage_case "too few arguments" "$VERSION" packages.txt
usage_case "too many arguments" "$VERSION" packages.txt gomods.txt 2 1 extra
usage_case "a non-integer bound" "$VERSION" packages.txt gomods.txt abc 1
usage_case "a non-integer interval" "$VERSION" packages.txt gomods.txt 2 1.5
usage_case "a zero interval" "$VERSION" packages.txt gomods.txt 2 0
usage_case "an empty packages file" "$VERSION" empty.txt gomods.txt 2 1
usage_case "an empty gomods file" "$VERSION" packages.txt empty.txt 2 1
usage_case "a missing packages file" "$VERSION" nowhere.txt gomods.txt 2 1
usage_case "a leading v on the version" "v$VERSION" packages.txt gomods.txt 2 1

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
