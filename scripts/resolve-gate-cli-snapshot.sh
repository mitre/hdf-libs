#!/usr/bin/env bash
#
# Prints the snapshot the CI gates build their CLI from, as key=value lines:
# tag, commit, version and lag. The newest snapshot tracks main without anyone
# editing a pin, and only the publishing workflow can create one of these tags,
# so the tag namespace is the trust boundary rather than anything checked here.
#
# Refuses: no snapshot tag at all; a tag whose commit does not have exactly one
# parent; a parent that is not on main, which is the claim that the code came
# through review; and a main that has run further past that parent than the
# allowed lag, so a publisher that has stopped is loud rather than silent.
#
# Usage: resolve-gate-cli-snapshot.sh [max-main-lag]   (default 10)

set -euo pipefail

usage() {
  echo "usage: ${0##*/} [max-main-lag]" >&2
  exit 2
}

refuse() {
  echo "$1" >&2
  exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/snapshot-version.sh
. "$script_dir/snapshot-version.sh"

[ $# -le 1 ] || usage
readonly MAX_LAG="${1:-10}"
[[ "$MAX_LAG" =~ ^[0-9]+$ ]] || usage

# main as this checkout sees it: a fetched remote ref when there is one, else the branch.
main_ref=""
for candidate in refs/remotes/origin/main refs/heads/main; do
  if git rev-parse --verify --quiet "$candidate" >/dev/null; then
    main_ref=$candidate
    break
  fi
done
[ -n "$main_ref" ] || refuse "no main ref in this checkout; expected refs/remotes/origin/main or refs/heads/main"

# The newest snapshot by version, which is the order the publisher issues them in.
newest_tag=""
newest_version=""
while IFS= read -r tag; do
  [ -n "$tag" ] || continue
  version=${tag#snapshots/v}
  [[ "$version" =~ $VERSION_PATTERN ]] || continue
  if [ -z "$newest_version" ] || version_newer "$version" "$newest_version"; then
    newest_tag=$tag
    newest_version=$version
  fi
done < <(git for-each-ref --format='%(refname:short)' 'refs/tags/snapshots/v*')

[ -n "$newest_tag" ] || refuse "no snapshots/v tag in this checkout matching the snapshot version shape"

commit=$(git rev-list -n1 "$newest_tag") ||
  refuse "$newest_tag does not resolve to a commit"

# A prepared commit is a single child of the main commit it was built from.
read -r _ parents <<< "$(git rev-list --parents -n1 "$commit")"
read -r -a parent_list <<< "$parents"
[ "${#parent_list[@]}" -eq 1 ] ||
  refuse "$newest_tag is at $commit with ${#parent_list[@]} parents; a prepared snapshot commit has exactly one"
parent=${parent_list[0]}

git merge-base --is-ancestor "$parent" "$main_ref" ||
  refuse "$newest_tag is at $commit, whose parent $parent is not on main; its code did not come through review"

lag=$(git rev-list --count "$parent..$main_ref")
[ "$lag" -le "$MAX_LAG" ] ||
  refuse "main is $lag commits past $newest_tag's parent $parent, over the allowed $MAX_LAG; the snapshot publisher looks stopped"

printf 'tag=%s\ncommit=%s\nversion=%s\nlag=%s\n' "$newest_tag" "$commit" "$newest_version" "$lag"
