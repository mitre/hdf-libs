#!/usr/bin/env bash
#
# Fails if a published Go module's consumer-reachable build graph depends on an
# in-repo module that a release never tags, or if a module in GO_MODULES could
# not be tagged correctly in the first place.
#
# Such a dependency works here and nowhere else: it resolves through a `replace`
# directive, and consumers ignore those. `go get` of the published module then
# fails outright. A local `go build ./...` cannot catch it — the replace makes
# that pass — which is how hdf-converters shipped unbuildable in v3.6.0-rc.2
# (hdf-libs-7pki).
#
# THIS SCRIPT FAILS CLOSED. Three earlier versions of it reported `ok` while the
# bug was present, so every step is defensive on purpose:
#
#   - GO_MODULES is parsed by bash itself, exactly as the workflow parses it,
#     and the run asserts it checked N of N. A regex parse silently dropped
#     entries whose quoting it did not anticipate, and the guard meant to catch
#     that shared the regex's blind spot, so the counts agreed while a module
#     vanished.
#   - Every `go list` result is checked. A module that yields no packages is an
#     error, never a pass.
#   - Membership in GO_MODULES is not sufficient. A module whose path lacks the
#     major-version suffix the release tag implies cannot be resolved by anyone
#     even once listed, so adding it to GO_MODULES is not a fix. That is the
#     most likely wrong turn a future reader will take.
#   - The graph is evaluated on several platforms. Build-constrained files are
#     invisible to a single-platform query, and shared/go/xsdvalidate already
#     contains a //go:build windows file.
#
# Packages under internal/ are excluded: Go's own rule makes them unreachable to
# consumers, which is the sanctioned home for test scaffolding. Test files are
# excluded because module-graph pruning means a consumer never resolves a
# package it does not import.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

RELEASE_WORKFLOW="${RELEASE_WORKFLOW:-.github/workflows/release.yml}"
readonly PREFIX="github.com/mitre/hdf-libs/"

# Platforms whose build constraints can hide an import. CGO_ENABLED=0 is the
# standard containerized consumer build.
readonly PLATFORMS=(
  "linux amd64 1"
  "linux amd64 0"
  "windows amd64 0"
  "darwin arm64 0"
)

# --- read GO_MODULES the way the workflow does, not with a regex ------------

go_modules_block="$(sed -n '/GO_MODULES=(/,/^          )/p' "$RELEASE_WORKFLOW")"
if [ -z "$go_modules_block" ]; then
  echo "error: could not find the GO_MODULES array in $RELEASE_WORKFLOW" >&2
  exit 1
fi

GO_MODULES=()
# shellcheck disable=SC2016 # the block is bash source, evaluated deliberately
if ! eval "$go_modules_block" 2>/dev/null; then
  echo "error: GO_MODULES in $RELEASE_WORKFLOW is not valid bash; cannot trust a parse of it" >&2
  exit 1
fi

declared="${#GO_MODULES[@]}"
if [ "$declared" -eq 0 ]; then
  echo "error: GO_MODULES parsed as empty in $RELEASE_WORKFLOW" >&2
  exit 1
fi

# --- the module paths a release publishes, and whether they CAN be tagged ---

published_paths=""
majors=""
for dir in "${GO_MODULES[@]}"; do
  if [ ! -f "$dir/go.mod" ]; then
    echo "error: '$dir' is listed in GO_MODULES but has no go.mod" >&2
    exit 1
  fi
  path="$(awk '/^module /{print $2; exit}' "$dir/go.mod")"
  if [ -z "$path" ]; then
    echo "error: could not read the module path from $dir/go.mod" >&2
    exit 1
  fi
  published_paths="$published_paths $path"
  case "$path" in
    */v[0-9]*) majors="$majors ${path##*/}" ;;
    *)         majors="$majors v1" ;;
  esac
done

# The release mints TAG="${mod}/${VERSION}" for every entry at one version, so
# every path must carry the same major suffix. A path without one cannot be
# tagged at v2+ and will resolve for nobody.
distinct_majors="$(printf '%s\n' $majors | sort -u | tr '\n' ' ')"
if [ "$(printf '%s\n' $majors | sort -u | grep -c .)" -ne 1 ]; then
  echo "error: GO_MODULES entries disagree on their major-version suffix:$distinct_majors" >&2
  echo "       A release tags them all at one version, so a module whose path lacks the" >&2
  echo "       matching /vN suffix cannot be resolved by a consumer. Listing it here does" >&2
  echo "       not publish it." >&2
  for dir in "${GO_MODULES[@]}"; do
    printf '       %-26s %s\n' "$dir" "$(awk '/^module /{print $2; exit}' "$dir/go.mod")" >&2
  done
  exit 1
fi

is_published() {
  case " $published_paths " in
    *" $1 "*) return 0 ;;
    *) return 1 ;;
  esac
}

# --- check each module on each platform -------------------------------------

failed=0
checked=0

for dir in "${GO_MODULES[@]}"; do
  module_ok=1
  offenders=""
  package_count=0

  for platform in "${PLATFORMS[@]}"; do
    read -r goos goarch cgo <<<"$platform"

    if ! packages="$(cd "$dir" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED="$cgo" go list ./... 2>&1)"; then
      echo "FAIL $dir [$goos/$goarch cgo=$cgo] — could not list packages, so nothing was checked:" >&2
      printf '%s\n' "$packages" | sed 's/^/    /' >&2
      module_ok=0
      continue
    fi

    checkable="$(printf '%s\n' "$packages" | grep -v '/internal/' || true)"
    [ -z "$checkable" ] && continue

    if ! deps="$(cd "$dir" && GOOS="$goos" GOARCH="$goarch" CGO_ENABLED="$cgo" \
        go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' $checkable 2>&1)"; then
      echo "FAIL $dir [$goos/$goarch cgo=$cgo] — could not resolve the build graph:" >&2
      printf '%s\n' "$deps" | sed 's/^/    /' >&2
      module_ok=0
      continue
    fi

    count="$(printf '%s\n' "$checkable" | grep -c .)"
    [ "$count" -gt "$package_count" ] && package_count="$count"

    for mod in $(printf '%s\n' "$deps" | grep "^$PREFIX" | sort -u); do
      is_published "$mod" || case " $offenders " in
        *" $mod "*) ;;
        *) offenders="$offenders $mod ($goos/$goarch cgo=$cgo)" ;;
      esac
    done
  done

  if [ "$package_count" -eq 0 ] && [ "$module_ok" -eq 1 ]; then
    echo "FAIL $dir — no consumer-reachable packages on any platform; refusing to report a pass" >&2
    module_ok=0
  fi

  if [ -n "$offenders" ]; then
    echo "FAIL $dir — consumer-reachable code depends on module(s) no release tags:"
    printf '%s\n' $offenders | paste -sd' ' - | sed 's/^/    /'
    echo "    A consumer running 'go get' on this module cannot resolve them."
    module_ok=0
  fi

  if [ "$module_ok" -eq 1 ]; then
    echo "ok   $dir ($package_count consumer-reachable packages)"
  fi
  [ "$module_ok" -eq 1 ] || failed=1
  checked=$((checked + 1))
done

if [ "$checked" -ne "$declared" ]; then
  echo "error: checked $checked of $declared GO_MODULES entries — a module was skipped" >&2
  exit 1
fi
echo "checked $checked of $declared modules on ${#PLATFORMS[@]} platforms"

if [ "$failed" -ne 0 ]; then
  cat >&2 <<'MSG'

Move the offending import out of the consumer-reachable build graph — an
internal/ package or a _test.go file — rather than adding a replace, which
consumers ignore. Adding the module to GO_MODULES is NOT a fix unless its path
already carries the major-version suffix the release tag implies.
MSG
  exit 1
fi
