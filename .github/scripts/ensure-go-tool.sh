#!/usr/bin/env bash
#
# Ensure a Go CLI tool binary is installed at the exact requested module
# version and host GOOS/GOARCH, reusing cached binaries verified via
# `go version -m` without executing them (preventing Rosetta false positives).
#
# Usage:
#   ensure-go-tool.sh --bin-dir
#   ensure-go-tool.sh <package-path> <version> [binary-name]
# Prints only the resolved directory or binary path to stdout; logs go to stderr.

set -euo pipefail

usage() {
  echo "usage: $0 [--bin-dir | <package-path> <version> [binary-name]]" >&2
  exit 2
}

go_env() {
  go env "$1" | tr -d '\r'
}

resolve_bin_dir() {
  local gobin gopath
  gobin="$(go_env GOBIN)"
  if [ -n "$gobin" ]; then
    printf '%s\n' "${gobin%/}"
    return 0
  fi
  gopath="$(go_env GOPATH)"
  [ -n "$gopath" ] || { echo "ensure-go-tool: go env GOPATH returned empty" >&2; exit 1; }
  printf '%s/bin\n' "${gopath%/}"
}

default_bin_name() {
  local p="$1" last parent
  last="${p##*/}"
  if [[ "$last" =~ ^v[0-9]+$ ]] && [[ "$p" == */* ]]; then
    parent="${p%/*}"
    last="${parent##*/}"
  fi
  printf '%s\n' "$last"
}

if [ "${1:-}" = "--bin-dir" ] && [ "$#" -eq 1 ]; then
  resolve_bin_dir
  exit 0
fi

if [ "$#" -lt 2 ] || [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
  usage
fi

pkg="$1"
version="$2"
bin_name="${3:-$(default_bin_name "$pkg")}"

bin_dir="$(resolve_bin_dir)"

goexe="$(go_env GOEXE)"
want_goos="$(go_env GOOS)"
want_goarch="$(go_env GOARCH)"
bin_path="${bin_dir}/${bin_name}${goexe}"

verify_binary() {
  local path="$1"
  [ -f "$path" ] && [ -x "$path" ] || return 1
  local meta
  meta="$(go version -m "$path" 2>/dev/null)" || return 1
  awk -F'\t' \
    -v pkg="$pkg" \
    -v ver="$version" \
    -v goos="$want_goos" \
    -v goarch="$want_goarch" '
      {
        gsub(/\r/, "")
        if ($2 == "path") got_path = $3
        else if ($2 == "mod") { got_mod = $3; got_ver = $4 }
        else if ($2 == "build" && $3 == "GOOS=" goos) ok_goos = 1
        else if ($2 == "build" && $3 == "GOARCH=" goarch) ok_goarch = 1
      }
      END {
        mod_match = (got_mod != "" && (pkg == got_mod || index(pkg, got_mod "/") == 1))
        if (got_path == pkg && mod_match && got_ver == ver && ok_goos == 1 && ok_goarch == 1) {
          exit 0
        }
        exit 1
      }
    ' <<< "$meta"
}

if verify_binary "$bin_path"; then
  printf 'ensure-go-tool: reusing %s (%s %s/%s)\n' "$bin_path" "$version" "$want_goos" "$want_goarch" >&2
  printf '%s\n' "$bin_path"
  exit 0
fi

printf 'ensure-go-tool: installing %s@%s -> %s (%s/%s)\n' "$pkg" "$version" "$bin_path" "$want_goos" "$want_goarch" >&2
go install "${pkg}@${version}" 1>&2

if ! verify_binary "$bin_path"; then
  echo "ensure-go-tool: installed binary failed buildinfo verification: $bin_path ($pkg@$version $want_goos/$want_goarch)" >&2
  exit 1
fi

printf '%s\n' "$bin_path"
