#!/usr/bin/env bash
#
# Fails if any module in go.work is untidy, or pins a sibling module at the
# zero pseudo-version.
#
# Tidiness: `go mod tidy -diff` writes nothing and exits non-zero when it would
# change go.mod or go.sum. (`go mod tidy` is single-module and ignores go.work,
# so no GOWORK setting is needed or honoured here.)
#
# Pins: a `go get` that DOWNGRADES a dependency below what a sibling module
# requires removes that sibling's require; the next tidy adds it back at
# v3.0.0-00010101000000-000000000000 because the replace directive resolves it
# locally. Tidy calls that tidy, every local build passes, and the module is
# unpublishable: a consumer cannot fetch a version no tag provides. Measured on
# hdf-cli with x/text 0.42.0 -> 0.41.0, in and out of workspace mode alike.
#
# Usage: check-go-mod-tidy.sh [<root>]   # root defaults to the repo root
#
# THIS SCRIPT FAILS CLOSED: a module that cannot be read or tidied is reported
# as untidy, never skipped.

set -euo pipefail

readonly MODULE_PREFIX="github.com/mitre/hdf-libs/"

if [ $# -ge 1 ]; then
  root="$1"
else
  root="$(git rev-parse --show-toplevel)"
fi
cd "$root"

if [ ! -f go.work ]; then
  echo "ERROR: no go.work under $root" >&2
  exit 1
fi

modules=$(go work edit -json | python3 -c '
import json, sys
for use in (json.load(sys.stdin).get("Use") or []):
    print(use["DiskPath"])
') || { echo "ERROR: could not read go.work" >&2; exit 1; }

# Emits "path version" per require, failing loudly on a go.mod Go cannot parse.
intra_repo_requires() {
  local json
  if ! json=$(go mod edit -json "$1" 2>&1); then
    echo "ERROR: cannot parse $1 — go mod edit said: $json" >&2
    return 1
  fi
  printf '%s' "$json" | python3 -c '
import json, sys
for req in (json.load(sys.stdin).get("Require") or []):
    print(req["Path"], req["Version"])
' || { echo "ERROR: could not read requires from $1" >&2; return 1; }
}

bad=0
checked=0
while IFS= read -r module; do
  [ -n "$module" ] || continue
  checked=$((checked + 1))
  if ! out=$(cd "$module" && go mod tidy -diff 2>&1); then
    echo "UNTIDY $module"
    printf '%s\n' "$out" | sed 's/^/    /'
    bad=$((bad + 1))
  fi
  requires=$(intra_repo_requires "$module/go.mod") || exit 1
  while read -r path version; do
    [ -n "$path" ] || continue
    case "$path" in
      "$MODULE_PREFIX"*) ;;
      *) continue ;;
    esac
    case "$version" in
      *-00010101000000-000000000000)
        echo "UNPINNED $module: $path at $version — a release cannot publish this; restore the sibling's version pin"
        bad=$((bad + 1))
        ;;
    esac
  done <<EOF2
$requires
EOF2
done <<EOF3
$modules
EOF3

if [ "$checked" -eq 0 ]; then
  echo "ERROR: go.work lists no modules" >&2
  exit 1
fi
if [ "$bad" -ne 0 ]; then
  echo "ERROR: $bad problem(s) across $checked module(s) — see UNTIDY/UNPINNED lines above; 'go mod tidy' fixes the former, restoring the pin fixes the latter" >&2
  exit 1
fi
echo "every module is tidy and every sibling pin is a real version ($checked checked)"
