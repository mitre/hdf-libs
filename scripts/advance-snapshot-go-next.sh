#!/usr/bin/env bash
#
# Moves the branch next to one snapshot's prepared commit. That commit carries the module
# tags, so `go get <module>@next` resolves to the snapshot version: Go's counterpart of the
# npm dist-tag next. Refuses a prepared commit that is not the version's snapshot tag or not
# a child of the source, a source not on main, and any move that would take next back to an
# older source. Pushes with a lease, reads next back, and prints next <commit> <version>.
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

[ $# -eq 3 ] || usage
readonly VERSION="$1" SOURCE="$2" PREPARED="$3"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+-next\.[0-9]+\.[0-9]+$ ]] || usage
[[ "$SOURCE" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$PREPARED" =~ ^[0-9a-f]{40}$ ]] || usage

readonly TAG="snapshots/v$VERSION"
git fetch --quiet --no-tags origin "+refs/heads/main:refs/remotes/origin/main" ||
  refuse "could not fetch main from origin"
git fetch --quiet --no-tags origin "+refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null ||
  refuse "$TAG does not exist on origin"

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
fi

git push --quiet --force-with-lease="refs/heads/next:$current" origin "$PREPARED:refs/heads/next" ||
  refuse "pushing next to $PREPARED failed"
observed=$(git ls-remote origin refs/heads/next | cut -f1)
[ "$observed" = "$PREPARED" ] ||
  refuse "next reads back as ${observed:-absent}, expected $PREPARED"
printf 'next\t%s\t%s\n' "$PREPARED" "$VERSION"
