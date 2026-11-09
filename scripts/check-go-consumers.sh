#!/usr/bin/env bash
#
# Proves the Go modules a snapshot just tagged are consumable. From a scratch
# module outside the checkout, with GOWORK=off and no replace directive, it
# fetches each inventoried module at the snapshot version through the public
# proxy, builds every package the module publishes and links each main package
# (that is what go install does), then requires every github.com/mitre/hdf-libs
# module in the resulting build list to be at exactly that version.
#
# Usage: check-go-consumers.sh <version> [<gomods-file>]
#   version      <major>.<minor>.<patch>[-prerelease], with or without a leading v
#   gomods-file  one go.mod path per line relative to the repo root, as the
#                snapshot's gomods.txt lists them; default: git ls-files '**/go.mod'

# check-go-module-consumers.sh lints the release workflow's pins at source;
# this checks the published result through the only graph a consumer has.
# Resolve and build only: nothing here runs a module's tests or code.
#
# THIS SCRIPT FAILS CLOSED: a module the proxy does not serve, a replace in
# the consumer, a module with no packages, or a sibling at any other version
# each exits nonzero naming what it saw.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> [<gomods-file>]" >&2
  exit 2
}

[ $# -ge 1 ] && [ $# -le 2 ] || usage
VERSION="v${1#v}"
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "ERROR: '$1' is not a module version" >&2
  exit 1
fi
readonly VERSION
readonly PREFIX="github.com/mitre/hdf-libs/"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

# --- the inventory, and the published module path behind each go.mod --------

if [ $# -eq 2 ]; then
  [ -f "$2" ] || fail "$2 is not a file"
  inventory="$(cat "$2")"
else
  inventory="$(cd "$root" && git ls-files '**/go.mod')"
fi

modules=()
while read -r gomod; do
  [ -n "$gomod" ] || continue
  case "$gomod" in
    go.mod | */go.mod) ;;
    *) fail "'$gomod' is not a go.mod path" ;;
  esac
  [ -f "$root/$gomod" ] || fail "$gomod is in the inventory but not in the checkout"
  path="$(awk '/^module /{print $2; exit}' "$root/$gomod")"
  [ -n "$path" ] || fail "$gomod has no module directive"
  case "$path" in
    "$PREFIX"*) ;;
    *) fail "$gomod declares $path, which is not under $PREFIX" ;;
  esac
  modules+=("$path")
done <<<"$inventory"
[ "${#modules[@]}" -gt 0 ] || fail "the inventory is empty"

# --- a scratch consumer outside the checkout, with a module cache of its own -

work="$(mktemp -d)"
case "$work" in
  "$root"/*) fail "$work is inside the checkout" ;;
esac
# The module cache is written read-only, so it must be opened before removal.
cleanup() {
  chmod -R u+w "$work" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

export GOWORK=off GOFLAGS=-mod=mod GOMODCACHE="$work/modcache"
mkdir -p "$work/consumer" "$work/bin"
cd "$work/consumer"
go mod init example.com/hdf-consumer

echo "consumer: $PWD"
echo "GOPROXY:  $(go env GOPROXY)"
echo "version:  $VERSION"
echo "modules:  ${#modules[@]}"

log="$work/go.log"
show_log() {
  sed 's/^/     /' "$log" >&2
}

# --- resolve every module at the snapshot version, through the proxy ---------

unserved=0
for module in "${modules[@]}"; do
  if go get "$module@$VERSION" >"$log" 2>&1; then
    echo "ok   get   $module@$VERSION"
  else
    echo "FAIL get   $module@$VERSION — go get failed:" >&2
    show_log
    unserved=1
  fi
done
[ "$unserved" -eq 0 ] || exit 1

# --- no replace: the point is the graph a consumer gets ----------------------

if [ "$(grep -c replace go.mod || true)" -ne 0 ]; then
  echo "FAIL the consumer's go.mod carries a replace directive; this is not the public graph:" >&2
  grep replace go.mod | sed 's/^/     /' >&2
  exit 1
fi

# --- build every published package; link every main package ------------------

for module in "${modules[@]}"; do
  if ! packages="$(go list -f '{{.ImportPath}} {{.Name}}' "$module/..." 2>"$log")"; then
    echo "FAIL list  $module — could not list its packages:" >&2
    show_log
    exit 1
  fi
  [ -n "$packages" ] || fail "$module publishes no packages; refusing to report a pass"
  if ! go build "$module/..." >"$log" 2>&1; then
    echo "FAIL build $module/...:" >&2
    show_log
    exit 1
  fi
  binaries=0
  while read -r main; do
    [ -n "$main" ] || continue
    if ! go build -o "$work/bin/" "$main" >"$log" 2>&1; then
      echo "FAIL build $main (main package):" >&2
      show_log
      exit 1
    fi
    binaries=$((binaries + 1))
  done <<<"$(awk '$2 == "main" {print $1}' <<<"$packages")"
  echo "ok   build $module ($(grep -c . <<<"$packages") packages, $binaries binaries)"
done

# --- one graph, one version --------------------------------------------------

if ! build_list="$(go list -m all 2>"$log")"; then
  echo "FAIL could not read the build list:" >&2
  show_log
  exit 1
fi

mismatched=0
seen=""
while read -r path version rest; do
  case "$path" in
    "$PREFIX"*) ;;
    *) continue ;;
  esac
  seen="$seen $path"
  if [ "$version" != "$VERSION" ] || [ -n "$rest" ]; then
    echo "FAIL $path resolved to ${version:-<none>}${rest:+ $rest}; the snapshot is $VERSION" >&2
    mismatched=1
  fi
done <<<"$build_list"
for module in "${modules[@]}"; do
  case " $seen " in
    *" $module "*) ;;
    *)
      echo "FAIL $module is absent from the build list; the snapshot is $VERSION" >&2
      mismatched=1 ;;
  esac
done
[ "$mismatched" -eq 0 ] || exit 1
echo "ok   every ${PREFIX}* module in the build list is $VERSION ($(wc -w <<<"$seen" | tr -d ' ') modules)"

echo "checked ${#modules[@]} modules: resolved, built and consistent at $VERSION"
