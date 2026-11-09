#!/usr/bin/env bash
#
# Waits until a snapshot is served: every @mitre/<name>@<version> on
# registry.npmjs.org, then every inventoried module's v<version>.info on
# proxy.golang.org, asking each unserved item again every <interval> seconds
# within one <bound> for both phases. Exits 0 once everything is served, 1 with
# the unserved items when the bound passes first, 1 when a module path needs the
# proxy's case escaping, and 2 on a usage error. Network access is through curl.
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

npm_url() { printf 'https://registry.npmjs.org/@mitre%%2f%s/%s' "$1" "$VERSION"; }
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

# --- one phase: poll the unserved items until none is left or the bound passes --

# wait_for <kind> <url-fn> <items...>: polls every unserved item each round,
# printing "<kind> <served>/<total> served[, <n> waiting: <items>]", and leaves
# the items still unserved at the bound in $unserved for the caller's message.
wait_for() {
  local kind="$1" url_fn="$2" total remaining
  shift 2
  total=$#
  unserved=("$@")
  while :; do
    local still=()
    for item in "${unserved[@]}"; do
      served "$("$url_fn" "$item")" || still+=("$item")
    done
    unserved=(${still[@]+"${still[@]}"})
    if [ "${#unserved[@]}" -eq 0 ]; then
      echo "$kind $total/$total served"
      return 0
    fi
    echo "$kind $((total - ${#unserved[@]}))/$total served, ${#unserved[@]} waiting: ${unserved[*]}"
    remaining=$((BOUND - SECONDS))
    [ "$remaining" -gt 0 ] || return 1
    sleep $(( remaining < INTERVAL ? remaining : INTERVAL ))
  done
}

# The proxy is asked only after the registry has shown the publication exists:
# asked for a tag before it is pushed, proxy.golang.org caches the not-found.
unserved=()
wait_for npm npm_url "${packages[@]}" || timed_out "${unserved[@]/#/@mitre/}" "${modules[@]}"
wait_for go go_url "${modules[@]}" || timed_out "${unserved[@]}"

echo "served: ${#packages[@]} npm packages and ${#modules[@]} Go modules at $VERSION after ${SECONDS}s"
