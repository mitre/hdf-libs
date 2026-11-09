#!/usr/bin/env bash
#
# Pins publish-snapshot-packages.sh offline: a fake curl answers one status per
# package from a fixture directory (404 unless a file says otherwise) and a fake
# npm records each call's argv and fails for the packages a fixture lists. The
# archives are empty files, since the script never opens them.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/publish-snapshot-packages.sh"

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

readonly VERSION=3.8.0-next.42548603920.1
readonly PACKAGES="hdf-pear hdf-apple hdf-plum hdf-fig"
readonly FLAGS="--access public --provenance --ignore-scripts --tag snapshot-staging \
--registry=https://registry.npmjs.org --@mitre:registry=https://registry.npmjs.org"

mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'CURL'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$*" >> "$FAKE_CURL_LOG"
url="${*##* }"
name="${url#*%2f}"
name="${name%%/*}"
if [ -f "$FAKE_CURL_CODES/$name" ]; then
  cat "$FAKE_CURL_CODES/$name"
else
  printf '404'
fi
CURL
cat > "$work/bin/npm" <<'NPM'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$*" >> "$FAKE_NPM_LOG"
n=$(wc -l < "$FAKE_NPM_LOG" | tr -d ' ')
printf '%s\n' "$@" > "$FAKE_NPM_CALLS/$n"
while IFS= read -r failing; do
  case "$2" in
    */mitre-"$failing"-*) echo "fake npm: refusing $failing" >&2; exit 1 ;;
  esac
done < "$FAKE_NPM_FAIL"
NPM
chmod +x "$work/bin/curl" "$work/bin/npm"

archives="$work/archives"
mkdir -p "$archives"
for pkg in $PACKAGES; do printf '%s\n' "$pkg"; done > "$work/packages.txt"
for pkg in $PACKAGES; do : > "$archives/mitre-$pkg-$VERSION.tgz"; done

# arrange <case>: fresh logs and fixtures for one run; the case's codes and
# failing packages are added by the caller before run.
arrange() {
  c="$work/$1"
  mkdir -p "$c/codes" "$c/calls"
  : > "$c/curl.log"; : > "$c/npm.log"; : > "$c/npm-fail"
  export FAKE_CURL_LOG="$c/curl.log" FAKE_CURL_CODES="$c/codes"
  export FAKE_NPM_LOG="$c/npm.log" FAKE_NPM_CALLS="$c/calls" FAKE_NPM_FAIL="$c/npm-fail"
}

# run [args...]: runs the script under the fakes; stdout, stderr and the exit
# code land in the case directory.
run() {
  PATH="$work/bin:$PATH" bash "$SCRIPT" "$@" > "$c/stdout" 2> "$c/stderr"
  echo $? > "$c/rc"
}

rc_is() { [ "$(cat "$c/rc")" -eq "$1" ]; }
npm_calls() { wc -l < "$c/npm.log" | tr -d ' '; }

arrange nothing-published
run "$VERSION" "$work/packages.txt" "$archives"
ok=0; rc_is 0 || ok=1
report "nothing published yet: exits 0" "$ok" "exit $(cat "$c/rc")"
ok=0; [ "$(npm_calls)" -eq 4 ] || ok=1
report "nothing published yet: one npm call per package" "$ok" "$(npm_calls) calls"
i=0
for pkg in $PACKAGES; do
  i=$((i + 1))
  verb="$(sed -n 1p "$c/calls/$i")"
  spec="$(sed -n 2p "$c/calls/$i")"
  ok=0
  [ "$verb" = publish ] || ok=1
  case "$spec" in
    /*/mitre-$pkg-$VERSION.tgz) ;;
    *) ok=1 ;;
  esac
  [ -f "$spec" ] || ok=1
  grep -qF -- "$FLAGS" "$c/npm.log" && [ "$(grep -cF -- "$FLAGS" "$c/npm.log")" -eq 4 ] || ok=1
  report "nothing published yet: call $i publishes $pkg by absolute path with every flag" "$ok" "$verb $spec"
done
ok=0; grep -qF 'published: 4, already published: 0, failed: 0' "$c/stdout" || ok=1
report "nothing published yet: summary counts four publications" "$ok" "$(cat "$c/stdout")"
ok=0; [ ! -s "$c/stderr" ] || ok=1
report "nothing published yet: stderr is empty" "$ok" "$(cat "$c/stderr")"

arrange mixed
printf '200' > "$c/codes/hdf-pear"; printf '200' > "$c/codes/hdf-plum"
run "$VERSION" "$work/packages.txt" "$archives"
ok=0; rc_is 0 || ok=1
report "mixed: exits 0" "$ok" "exit $(cat "$c/rc")"
ok=0; [ "$(npm_calls)" -eq 2 ] || ok=1
report "mixed: only the unpublished pair reaches npm" "$ok" "$(npm_calls) calls"
ok=0; ! grep -qF 'mitre-hdf-pear-' "$c/npm.log" && ! grep -qF 'mitre-hdf-plum-' "$c/npm.log" || ok=1
report "mixed: a version the registry holds is not published" "$ok" "$(cat "$c/npm.log")"
ok=0; grep -qF 'mitre-hdf-apple-' "$c/npm.log" && grep -qF 'mitre-hdf-fig-' "$c/npm.log" || ok=1
report "mixed: the two absent versions are published" "$ok" "$(cat "$c/npm.log")"
ok=0
grep -qF "already published: @mitre/hdf-pear@$VERSION" "$c/stdout" &&
  grep -qF "already published: @mitre/hdf-plum@$VERSION" "$c/stdout" || ok=1
report "mixed: the already-published line names each skipped package" "$ok" "$(cat "$c/stdout")"
ok=0; grep -qF 'published: 2, already published: 2, failed: 0' "$c/stdout" || ok=1
report "mixed: summary counts two skips" "$ok" "$(cat "$c/stdout")"

arrange one-fails
printf 'hdf-apple\n' > "$c/npm-fail"
run "$VERSION" "$work/packages.txt" "$archives"
ok=0; rc_is 1 || ok=1
report "one publish fails: exits 1" "$ok" "exit $(cat "$c/rc")"
ok=0; [ "$(npm_calls)" -eq 4 ] || ok=1
report "one publish fails: every package is still attempted" "$ok" "$(npm_calls) calls"
ok=0
[ "$(sed -n 2p "$c/calls/3")" = "$archives/mitre-hdf-plum-$VERSION.tgz" ] &&
  [ "$(sed -n 2p "$c/calls/4")" = "$archives/mitre-hdf-fig-$VERSION.tgz" ] || ok=1
report "one publish fails: the later packages are published in file order" "$ok" "$(cat "$c/npm.log")"
ok=0; grep -qF 'published: 3, already published: 0, failed: 1' "$c/stdout" || ok=1
report "one publish fails: summary counts one failure" "$ok" "$(cat "$c/stdout")"
ok=0; grep -qF "@mitre/hdf-apple@$VERSION" "$c/stderr" || ok=1
report "one publish fails: stderr names the failed package" "$ok" "$(cat "$c/stderr")"
ok=0; ! grep -qF 'hdf-pear' "$c/stderr" && ! grep -qF 'hdf-plum' "$c/stderr" && ! grep -qF 'hdf-fig' "$c/stderr" || ok=1
report "one publish fails: stderr names no other package" "$ok" "$(cat "$c/stderr")"

arrange unreadable
printf '000' > "$c/codes/hdf-apple"; printf '503' > "$c/codes/hdf-plum"
run "$VERSION" "$work/packages.txt" "$archives"
ok=0; rc_is 1 || ok=1
report "registry unreadable: exits 1" "$ok" "exit $(cat "$c/rc")"
ok=0; [ "$(npm_calls)" -eq 2 ] || ok=1
report "registry unreadable: the unreadable pair is not published" "$ok" "$(cat "$c/npm.log")"
ok=0; ! grep -qF 'mitre-hdf-apple-' "$c/npm.log" && ! grep -qF 'mitre-hdf-plum-' "$c/npm.log" || ok=1
report "registry unreadable: no npm call carries an unreadable package" "$ok" "$(cat "$c/npm.log")"
ok=0
grep -qF "could not read the registry for @mitre/hdf-apple@$VERSION (HTTP 000)" "$c/stderr" &&
  grep -qF "could not read the registry for @mitre/hdf-plum@$VERSION (HTTP 503)" "$c/stderr" || ok=1
report "registry unreadable: stderr carries each status code" "$ok" "$(cat "$c/stderr")"
ok=0; grep -qF 'published: 2, already published: 0, failed: 2' "$c/stdout" || ok=1
report "registry unreadable: summary counts both as failed" "$ok" "$(cat "$c/stdout")"

arrange no-archive
printf 'hdf-pear\nhdf-kiwi\n' > "$c/packages.txt"
run "$VERSION" "$c/packages.txt" "$archives"
ok=0; rc_is 2 || ok=1
report "usage: a listed package without an archive exits 2" "$ok" "exit $(cat "$c/rc")"
ok=0; [ ! -s "$c/npm.log" ] && [ ! -s "$c/curl.log" ] || ok=1
report "usage: a listed package without an archive calls neither npm nor curl" "$ok" "$(cat "$c/npm.log" "$c/curl.log")"
ok=0; grep -qF "mitre-hdf-kiwi-$VERSION.tgz" "$c/stderr" || ok=1
report "usage: the missing archive is named on stderr" "$ok" "$(cat "$c/stderr")"

arrange missing-args
run "$VERSION" "$work/packages.txt"
ok=0; rc_is 2 && [ ! -s "$c/npm.log" ] || ok=1
report "usage: missing arguments exit 2" "$ok" "exit $(cat "$c/rc")"
run "$VERSION" "$work/packages.txt" "$archives" extra
ok=0; rc_is 2 || ok=1
report "usage: an extra argument exits 2" "$ok" "exit $(cat "$c/rc")"
run "$VERSION" "$work/nowhere.txt" "$archives"
ok=0; rc_is 2 || ok=1
report "usage: a missing packages file exits 2" "$ok" "exit $(cat "$c/rc")"
: > "$c/empty.txt"
run "$VERSION" "$c/empty.txt" "$archives"
ok=0; rc_is 2 || ok=1
report "usage: an empty packages file exits 2" "$ok" "exit $(cat "$c/rc")"
run "$VERSION" "$work/packages.txt" "$work/nowhere"
ok=0; rc_is 2 && [ ! -s "$c/npm.log" ] || ok=1
report "usage: a missing archives directory exits 2" "$ok" "exit $(cat "$c/rc")"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
