#!/usr/bin/env bash
#
# Moves the npm dist-tag next to one snapshot version for every package listed,
# then reads next back from the registry until each package reports that version
# or the bound elapses, and prints one tab-separated row per package:
# <name> <observed next> <ok|stale>. Stdout carries only poll: progress lines
# and that table; failures go to stderr.
#
# Usage: promote-snapshot-next.sh <version> <packages-file> [<bound-s>] [<interval-s>]

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> <packages-file> [<bound-seconds>] [<interval-seconds>]" >&2
  exit 2
}

[ $# -ge 2 ] && [ $# -le 4 ] || usage
readonly VERSION="$1"
packages_file="$2"
bound="${3:-300}"
interval="${4:-15}"
[[ "$bound" =~ ^[0-9]+$ ]] || usage
[[ "$interval" =~ ^[1-9][0-9]*$ ]] || usage
[ -s "$packages_file" ] || usage

packages=()
while IFS= read -r name || [ -n "$name" ]; do
  [ -n "$name" ] && packages+=("$name")
done < "$packages_file"
[ "${#packages[@]}" -gt 0 ] || usage

registry=(--registry=https://registry.npmjs.org --@mitre:registry=https://registry.npmjs.org)

# The registry is the oracle for what next points at, not a previous run's log,
# so every package is re-added on every run rather than only the ones a log missed.
add_failed=""
for name in "${packages[@]}"; do
  npm dist-tag add "@mitre/$name@$VERSION" next "${registry[@]}" >&2 ||
    add_failed="$add_failed $name"
done

read_next() {
  local doc next
  doc=$(curl --silent --max-time 30 "https://registry.npmjs.org/-/package/@mitre%2f$1/dist-tags") || doc=''
  next=$(printf '%s' "$doc" | jq -r '.next // "absent"' 2>/dev/null) || next=''
  printf '%s\n' "${next:-absent}"
}

# npm applies dist-tag writes asynchronously and an acknowledged write can still fail to
# land, so each package is read back until it reports the version.
observed=()
for name in "${packages[@]}"; do
  observed+=("")
done
deadline=$((SECONDS + bound))
while :; do
  pending=0
  for i in "${!packages[@]}"; do
    [ "${observed[$i]}" = "$VERSION" ] && continue
    observed[i]="$(read_next "${packages[$i]}")"
    [ "${observed[$i]}" = "$VERSION" ] || pending=$((pending + 1))
  done
  echo "poll: $pending of ${#packages[@]} packages not yet at next=$VERSION"
  [ "$pending" -gt 0 ] || break
  remaining=$((deadline - SECONDS))
  [ "$remaining" -gt 0 ] || break
  sleep $((interval < remaining ? interval : remaining))
done

stale=""
for i in "${!packages[@]}"; do
  if [ "${observed[$i]}" = "$VERSION" ]; then
    printf '%s\t%s\tok\n' "${packages[$i]}" "${observed[$i]}"
  else
    printf '%s\t%s\tstale\n' "${packages[$i]}" "${observed[$i]}"
    stale="$stale $i"
  fi
done

rc=0
if [ -n "$add_failed" ]; then
  echo "dist-tag add failed for:$add_failed" >&2
  rc=1
fi
if [ -n "$stale" ]; then
  for i in $stale; do
    echo "${packages[$i]}: next is ${observed[$i]}, expected $VERSION" >&2
  done
  echo "partial promotion: re-run the failed publish job; do not fix next by hand" >&2
  rc=1
fi
exit "$rc"
