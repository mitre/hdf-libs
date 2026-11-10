#!/usr/bin/env bash
#
# Moves the branch next to one snapshot's prepared commit. That commit carries the module
# tags, so `go get <module>@next` resolves to the snapshot version: Go's counterpart of the
# npm dist-tag next. Refuses a prepared commit that is not the version's snapshot tag or not
# a child of the source, a source not on main, a source behind main's tip when next does
# not yet exist, and any move that would take next back to an older source or to an older
# snapshot of the same source. Pushes with a lease, reads next back, and prints
# next <commit> <version>.
#
# Usage: advance-snapshot-go-next.sh <version> <source-sha> <prepared-sha>

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> <source-sha> <prepared-sha>" >&2
  exit 2
}

refuse() {
  echo "$1" >&2
  exit 1
}

readonly VERSION_PATTERN='^([0-9]+)\.([0-9]+)\.([0-9]+)-next\.([0-9]+)\.([0-9]+)$'

# Succeeds when snapshot version $1 is strictly newer than $2. Versions order by release,
# then workflow run ID, then attempt, which is the order the workflow issues them in.
version_newer() {
  local -a a b
  local i
  [[ "$1" =~ $VERSION_PATTERN ]] && a=("${BASH_REMATCH[@]:1}") || return 1
  [[ "$2" =~ $VERSION_PATTERN ]] && b=("${BASH_REMATCH[@]:1}") || return 1
  for i in 0 1 2 3 4; do
    ((10#${a[i]} > 10#${b[i]})) && return 0
    ((10#${a[i]} < 10#${b[i]})) && return 1
  done
  return 1
}

# Prints the snapshot version tagged on commit $1 on origin, or nothing when it carries no
# snapshot tag. Fails when the tags cannot be listed or the commit carries more than one.
snapshot_version_of() {
  local listing sha ref version found=""
  listing=$(git ls-remote --tags origin 'refs/tags/snapshots/v*') || return 1
  while IFS=$'\t' read -r sha ref; do
    [ "$sha" = "$1" ] || continue
    version=${ref#refs/tags/snapshots/v}
    version=${version%^\{\}}
    [[ "$version" =~ $VERSION_PATTERN ]] || continue
    [ -z "$found" ] || [ "$found" = "$version" ] || return 1
    found=$version
  done <<< "$listing"
  printf '%s' "$found"
}

[ $# -eq 3 ] || usage
readonly VERSION="$1" SOURCE="$2" PREPARED="$3"
[[ "$VERSION" =~ $VERSION_PATTERN ]] || usage
[[ "$SOURCE" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$PREPARED" =~ ^[0-9a-f]{40}$ ]] || usage

readonly TAG="snapshots/v$VERSION"
git fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main" ||
  refuse "could not fetch main from origin"
git fetch --quiet --no-tags origin "+refs/tags/$TAG:refs/tags/$TAG" ||
  refuse "$TAG could not be fetched from origin"

tagged=$(git rev-parse --verify --quiet "refs/tags/$TAG^{commit}") ||
  refuse "$TAG does not name a commit"
[ "$tagged" = "$PREPARED" ] ||
  refuse "$TAG is on $tagged, not the prepared commit $PREPARED"
[ "$(git show -s --format=%P "$PREPARED")" = "$SOURCE" ] ||
  refuse "the parent of the prepared commit $PREPARED is not the source $SOURCE"
git merge-base --is-ancestor "$SOURCE" refs/remotes/origin/main ||
  refuse "the source $SOURCE is not on main"

current=$(git ls-remote origin refs/heads/next | cut -f1)
if [ "$current" = "$PREPARED" ]; then
  echo "next is already at $PREPARED" >&2
  printf 'next\t%s\t%s\n' "$PREPARED" "$VERSION"
  exit 0
fi
if [ -n "$current" ]; then
  git fetch --quiet --no-tags origin "+refs/heads/next:refs/remotes/origin/next" ||
    refuse "could not fetch the current next $current"
  # The source a prepared commit was built from is its parent.
  built_from=$(git rev-parse --verify --quiet "$current^1") ||
    refuse "the current next $current has no parent to compare with"
  git merge-base --is-ancestor "$built_from" "$SOURCE" ||
    refuse "next is at $current, built from $built_from, which $SOURCE does not descend from; refusing to move next back"
  # Ancestry is reflexive, so it cannot order two snapshots of one source, such as a
  # re-run of an older run after a newer run of the same commit; their versions can.
  if [ "$built_from" = "$SOURCE" ]; then
    current_version=$(snapshot_version_of "$current") ||
      refuse "could not read a single snapshot version for the current next $current"
    [ -n "$current_version" ] ||
      refuse "the current next $current has no snapshot tag to compare $VERSION with"
    version_newer "$VERSION" "$current_version" ||
      refuse "next is at $current, tagged snapshots/v$current_version from the same source $SOURCE, which $VERSION does not follow; refusing to move next back"
  fi
else
  # With no branch to order against, the tip is the only thing that says this snapshot is
  # the current one, so a source main has moved past cannot create next. Only this case
  # needs it: once next exists, the checks above order the move.
  tip=$(git rev-parse --verify refs/remotes/origin/main) ||
    refuse "could not read main from origin"
  [ "$SOURCE" = "$tip" ] ||
    refuse "next does not exist and the source $SOURCE is not main's tip $tip; refusing to create next from a snapshot main has moved past"
fi

git push --quiet --force-with-lease="refs/heads/next:$current" origin "$PREPARED:refs/heads/next" ||
  refuse "pushing next to $PREPARED failed"
observed=$(git ls-remote origin refs/heads/next | cut -f1)
[ "$observed" = "$PREPARED" ] ||
  refuse "next reads back as ${observed:-absent}, expected $PREPARED"
printf 'next\t%s\t%s\n' "$PREPARED" "$VERSION"
