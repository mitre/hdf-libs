#!/usr/bin/env bash
#
# Waits until a snapshot is served: every @mitre/<name>@<version> tarball on
# registry.npmjs.org and every inventoried module's v<version>.info on
# proxy.golang.org, polling unserved items from both registries together each
# round every <interval> seconds within one shared <bound>. Exits 0 once
# everything is served, 1 with the remaining unserved items when the bound
# passes first, 1 when a module path needs the proxy's case escaping, and 2 on
# a usage error. Network access is through curl.
#
# Usage: wait-for-snapshot-publication.sh <version> <packages-file> <gomods-file>
#          [<bound-seconds, default 600>] [<interval-seconds, default 30>]

# version: <major>.<minor>.<patch>[-prerelease], without a leading v.
# packages-file: one short npm package name per line (hdf-converters, for @mitre/).
# gomods-file: one go.mod path per line, relative to the current directory; the
# module path is read from each file's module directive.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> <packages-file> <gomods-file> [<bound-seconds>] [<interval-seconds>]" >&2
  exit 2
}

[ $# -ge 3 ] && [ $# -le 5 ] || usage
VERSION="$1"
PACKAGES="$2"
GOMODS="$3"
BOUND="${4:-600}"
INTERVAL="${5:-30}"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || usage
[[ "$BOUND" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$INTERVAL" =~ ^[1-9][0-9]*$ ]] || usage
[ -f "$PACKAGES" ] && [ -f "$GOMODS" ] || usage
readonly VERSION BOUND INTERVAL

# --- the inventory: package names, and the module path behind each go.mod -----

packages=()
while IFS= read -r name || [ -n "$name" ]; do
  [ -n "$name" ] || continue
  packages+=("$name")
done < "$PACKAGES"
[ "${#packages[@]}" -gt 0 ] || usage

modules=()
while IFS= read -r gomod || [ -n "$gomod" ]; do
  [ -n "$gomod" ] || continue
  [ -f "$gomod" ] || usage
  path="$(awk '/^module /{print $2; exit}' "$gomod")"
  [ -n "$path" ] || usage
  if [[ "$path" == *[[:upper:]]* ]]; then
    echo "ERROR: $path: the proxy's case escaping is not implemented for this module path" >&2
    exit 1
  fi
  modules+=("$path")
done < "$GOMODS"
[ "${#modules[@]}" -gt 0 ] || usage

# --- one URL per artifact, one curl per ask -----------------------------------

# The tarball, not the version document: the document answers minutes before
# the tarball is served, and the install check needs the tarball.
npm_url() { printf 'https://registry.npmjs.org/@mitre/%s/-/%s-%s.tgz' "$1" "$1" "$VERSION"; }
go_url() { printf 'https://proxy.golang.org/%s/@v/v%s.info' "$1" "$VERSION"; }

# served <url>: 0 when the URL answers 200; any other code or a curl failure is 1
served() {
  local code
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 30 "$1")" || code=000
  [ "$code" = 200 ]
}

# --- the timeout message --------------------------------------------------------

# timed_out <still-waiting...>: the four-part failure on stderr, then exit 1
timed_out() {
  echo "$VERSION: not every artifact was served within ${BOUND}s" >&2
  echo "  published: the versions on the registry are immutable and stay published" >&2
  echo "  not run: the consumer install checks did not run" >&2
  echo "  not advanced: next was not moved for any package" >&2
  echo "  recover: re-run the failed publish job once the registry and proxy serve the versions (still waiting: $*)" >&2
  exit 1
}

# --- shared polling loop: poll unserved npm packages and Go modules each round --
#
# Snapshot tags are pushed atomically by snapshot.yml's tag job before publish
# runs (`needs: [prepare, build, tag]`), and snapshot.yml is the sole caller,
# so polling proxy.golang.org alongside registry.npmjs.org cannot query
# untagged commits or cache premature not-found responses.

# poll_unserved <kind> <url-fn> <total> <items...>: polls each unserved item
# once, prints "<kind> <served>/<total> served[, <n> waiting: <items>]", and
# stores the remaining unserved items in _poll_still (bash 3.2 compatible).
_poll_still=()
poll_unserved() {
  local kind="$1" url_fn="$2" total="$3" item
  shift 3
  _poll_still=()
  for item in "$@"; do
    served "$("$url_fn" "$item")" || _poll_still+=("$item")
  done
  if [ "${#_poll_still[@]}" -eq 0 ]; then
    echo "$kind $total/$total served"
  else
    echo "$kind $((total - ${#_poll_still[@]}))/$total served, ${#_poll_still[@]} waiting: ${_poll_still[*]}"
  fi
}

npm_total=${#packages[@]}
go_total=${#modules[@]}
unserved_npm=("${packages[@]}")
unserved_go=("${modules[@]}")

while :; do
  if [ "${#unserved_npm[@]}" -gt 0 ]; then
    poll_unserved npm npm_url "$npm_total" "${unserved_npm[@]}"
    unserved_npm=(${_poll_still[@]+"${_poll_still[@]}"})
  fi

  if [ "${#unserved_go[@]}" -gt 0 ]; then
    poll_unserved go go_url "$go_total" "${unserved_go[@]}"
    unserved_go=(${_poll_still[@]+"${_poll_still[@]}"})
  fi

  if [ "${#unserved_npm[@]}" -eq 0 ] && [ "${#unserved_go[@]}" -eq 0 ]; then
    break
  fi

  remaining=$((BOUND - SECONDS))
  if [ "$remaining" -le 0 ]; then
    still_waiting=()
    if [ "${#unserved_npm[@]}" -gt 0 ]; then
      still_waiting+=("${unserved_npm[@]/#/@mitre/}")
    fi
    if [ "${#unserved_go[@]}" -gt 0 ]; then
      still_waiting+=("${unserved_go[@]}")
    fi
    timed_out "${still_waiting[@]}"
  fi
  sleep $(( remaining < INTERVAL ? remaining : INTERVAL ))
done

echo "served: $npm_total npm packages and $go_total Go modules at $VERSION after ${SECONDS}s"
