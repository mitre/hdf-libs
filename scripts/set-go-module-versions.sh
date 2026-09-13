#!/usr/bin/env bash
#
# Rewrites every intra-repo `require` in every go.mod to one exact version, so
# the commit a release tags names sibling versions that the same release tags.
#
# Go reads a module's go.mod from the tagged commit and ignores its `replace`
# directives, so a tag whose requires name a version nobody publishes yields a
# module that resolves for no one. Local builds cannot catch it — the replaces
# make them pass — which is how every pre-release through v3.6.0-rc.4 shipped
# unbuildable (hdf-libs-k5wgs).
#
# Run it as part of the "prepare release" commit, BEFORE tagging, with the exact
# version being released — pre-release suffix included:
#
#   scripts/set-go-module-versions.sh v3.6.0-rc.5
#   scripts/set-go-module-versions.sh v3.6.0
#
# This mirrors what etcd's release_mod.sh and opentelemetry-go's multimod do.
#
# THIS SCRIPT FAILS CLOSED. It rewrites with `go mod edit` rather than a regex —
# a first attempt with sed silently missed a require carrying a trailing comment
# — and then re-reads every file to prove no intra-repo require names anything
# but the target. A rewrite that reports success while leaving one behind is the
# failure this guards against, because the tag is published before anyone looks.

set -euo pipefail

readonly MODULE_PREFIX="github.com/mitre/hdf-libs/"

usage() {
  echo "usage: ${0##*/} <version>            # e.g. v3.6.0-rc.5, v3.6.0" >&2
  echo "       ${0##*/} <version> <root>     # root defaults to the repo root" >&2
  exit 2
}

[ $# -ge 1 ] || usage
readonly VERSION="$1"

# A bare major-version tag would resolve to a different module path, and a
# version without the leading v is not a Go version at all.
if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "ERROR: '$VERSION' is not a semantic version (want vMAJOR.MINOR.PATCH[-prerelease])" >&2
  exit 1
fi

if [ $# -ge 2 ]; then
  root="$2"
else
  root="$(git rev-parse --show-toplevel)"
fi
cd "$root"

# The workspace would otherwise resolve these through its own use list, which is
# exactly the local-only view this script exists to look past.
export GOWORK=off

# Emits "path version" per require. Runs as a plain command substitution, never
# inside a process substitution: a failure there is invisible to `set -e`, which
# is how an earlier version of this script printed success over a traceback and
# exited 0 with a pin left unrewritten.
intra_repo_requires() {
  local json
  if ! json=$(go mod edit -json "$1" 2>&1); then
    echo "ERROR: cannot parse $1 — go mod edit said: $json" >&2
    return 1
  fi
  printf '%s' "$json" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
for req in (doc.get("Require") or []):
    print(req["Path"], req["Version"])
' || { echo "ERROR: could not read requires from $1" >&2; return 1; }
}

# Go derives a module path's major version from its /vN suffix, so a pin whose
# major disagrees with the path is one Go itself refuses. Rewriting into that
# shape would swap one unresolvable pin for another.
major_matches_path() {
  local path="$1" version="$2" major suffix
  major="${version%%.*}"            # v3.6.0-rc.5 -> v3
  case "$path" in
    */v[0-9]|*/v[0-9][0-9]) suffix="/${path##*/}" ;;
    *) suffix="" ;;
  esac
  if [ -n "$suffix" ]; then
    [ "$suffix" = "/$major" ]
  else
    [ "$major" = "v0" ] || [ "$major" = "v1" ]
  fi
}

# Read into an array without mapfile: macOS ships bash 3.2, where it does not exist.
gomods=()
while IFS= read -r found; do
  gomods+=("$found")
done < <(find . -name go.mod -not -path '*/node_modules/*' | sort)
if [ "${#gomods[@]}" -eq 0 ]; then
  echo "ERROR: no go.mod files found under $root" >&2
  exit 1
fi

rewritten=0

for gomod in "${gomods[@]}"; do
  requires=$(intra_repo_requires "$gomod") || exit 1
  while read -r path version; do
    [ -n "$path" ] || continue
    case "$path" in
      "$MODULE_PREFIX"*) ;;
      *) continue ;;
    esac
    [ "$version" = "$VERSION" ] && continue
    if ! major_matches_path "$path" "$VERSION"; then
      echo "ERROR: $gomod requires $path, whose path cannot carry $VERSION." >&2
      echo "       Give the module the major-version suffix its tag implies, or tag it on its own line." >&2
      exit 1
    fi
    go mod edit -require="${path}@${VERSION}" "$gomod"
    rewritten=$((rewritten + 1))
  done <<EOF
$requires
EOF
done

# Prove it, rather than trusting the loop above: re-read every file and fail on
# any intra-repo require that does not name the target version.
stragglers=0
for gomod in "${gomods[@]}"; do
  requires=$(intra_repo_requires "$gomod") || exit 1
  while read -r path version; do
    [ -n "$path" ] || continue
    case "$path" in
      "$MODULE_PREFIX"*) ;;
      *) continue ;;
    esac
    [ "$version" = "$VERSION" ] && continue
    echo "FAIL $gomod: $path is still at $version, wanted $VERSION" >&2
    stragglers=$((stragglers + 1))
  done <<EOF
$requires
EOF
done

if [ "$stragglers" -ne 0 ]; then
  echo "ERROR: $stragglers intra-repo require(s) were not rewritten — do not tag this commit" >&2
  exit 1
fi

echo "rewrote $rewritten intra-repo require(s) to $VERSION across ${#gomods[@]} go.mod files"
