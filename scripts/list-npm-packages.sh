#!/usr/bin/env bash
#
# Prints every publishable @mitre/hdf-* workspace package directory, one per
# line, dependencies before dependents. Every publication path (CI packing,
# pre-release smoke test, formal release, main snapshots) reads this list, so a
# new package reaches all of them or none; the hand-kept arrays it replaces had
# already drifted from the dependency order they claimed.
#
# Usage: list-npm-packages.sh [<root>]      # root defaults to the repo root

set -euo pipefail

if [ $# -ge 1 ]; then
  root="$1"
else
  root="$(git rev-parse --show-toplevel)"
fi
cd "$root"

shopt -s nullglob
manifests=(hdf-*/package.json)
if [ "${#manifests[@]}" -eq 0 ]; then
  echo "ERROR: no hdf-*/package.json under $root" >&2
  exit 1
fi

# Kahn's algorithm in jq: each layer is every unlisted package whose workspace
# dependencies are all listed, sorted so the order is stable between runs.
jq -rn '
  [inputs
    | select(.private != true and (.name | type == "string" and startswith("@mitre/hdf-")))
    | {dir: (input_filename | sub("/package.json$"; "")), name,
       deps: ([.dependencies, .peerDependencies, .optionalDependencies] | map(. // {} | keys[]))}] as $pkgs
  | if ($pkgs | length) == 0 then error("no publishable @mitre/hdf-* package found") else . end
  | ($pkgs | map(.name)) as $names
  | ($pkgs | map({key: .name, value: (.deps | map(select(. as $d | $names | index($d) != null)) | unique)}) | from_entries) as $deps
  | ($pkgs | map({key: .name, value: .dir}) | from_entries) as $dirs
  | def layer(done): [$names[] | select(. as $n | (done | index($n)) == null and ($deps[$n] | all(. as $d | (done | index($d)) != null)))] | sort;
  def topo(done):
    if (done | length) == ($names | length) then done
    else layer(done) as $ready
      | if ($ready | length) == 0 then error("dependency cycle among " + (($names - done) | sort | join(", ")))
        else topo(done + $ready) end
    end;
  topo([])[] | $dirs[.]
' "${manifests[@]}"
