#!/usr/bin/env bash
# Install and import the packages outside the workspace, as an npm consumer:
# from a directory of packed tarballs, or with --registry-version from the
# public registry at the exact version every published sibling must share.
set -euo pipefail

scripts_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
registry=https://registry.npmjs.org/

usage() {
  echo "usage: $0 <directory containing package tarballs>" >&2
  echo "       $0 --registry-version <version>" >&2
  exit 2
}

add_dependency() { # <consumer> <name> <spec>
  jq --arg name "$2" --arg spec "$3" '.dependencies[$name] = $spec' "$1/package.json" > "$1/manifest.json"
  mv "$1/manifest.json" "$1/package.json"
}

# One @mitre/<pkg>@<version> per inventory line, named from each package manifest.
registry_specs() { # <repo root> <version>
  local inventory dir name
  inventory=$("$scripts_dir/list-npm-packages.sh" "$1") || return 1
  while IFS= read -r dir; do
    name=$(jq -er .name "$1/$dir/package.json") || return 1
    printf '%s@%s\n' "$name" "$2"
  done <<< "$inventory"
}

# Every @mitre/* in the lockfile, nested ones included, must be the one version, and
# there must be exactly as many as were requested: a lockfile that resolved fewer is
# not the graph that was asked for, however consistent what remains looks.
assert_lockfile_versions() { # <package-lock.json> <version> <expected count>
  local entries checked mismatches
  entries='[.packages | to_entries[] | select(.key | test("(^|/)node_modules/@mitre/[^/]+$"))]'
  checked=$(jq "$entries | length" "$1") || return 1
  if [ "$checked" -eq 0 ]; then
    echo "ERROR: no @mitre package in $1" >&2
    return 1
  fi
  mismatches=$(jq -r --arg version "$2" "$entries"'[] | select(.value.version != $version)
    | "ERROR: \(.key | sub(".*node_modules/"; "")) at \(.key) is \(.value.version), expected \($version)"' "$1") || return 1
  if [ -n "$mismatches" ]; then
    printf '%s\n' "$mismatches" >&2
    return 1
  fi
  if [ "$checked" -ne "$3" ]; then
    echo "ERROR: $1 holds $checked @mitre packages, but $3 were requested" >&2
    return 1
  fi
  echo "Every @mitre package in package-lock.json ($checked) is $2"
}

import_dependencies() {
  node --input-type=module -e 'import fs from "node:fs"; for (const name of Object.keys(JSON.parse(fs.readFileSync("package.json")).dependencies)) { await import(name); console.log("Imported", name); }'
}

main() {
  local mode archives version tarballs archive specs spec name
  if [ "$#" -eq 2 ] && [ "$1" = --registry-version ] && [ -n "$2" ]; then
    mode=registry
    version=$2
  elif [ "$#" -eq 1 ] && [ -d "$1" ]; then
    mode=tarballs
    archives=$(cd "$1" && pwd)
  else
    usage
  fi

  consumer=$(mktemp -d)  # not local: the EXIT trap removes it after main returns
  trap 'rm -rf "$consumer"' EXIT
  printf '{"private":true,"type":"module","dependencies":{}}\n' > "$consumer/package.json"

  if [ "$mode" = tarballs ]; then
    shopt -s nullglob
    tarballs=("$archives"/*.tgz)
    if [ "${#tarballs[@]}" -eq 0 ]; then
      echo 'No package tarballs to check' >&2
      exit 1
    fi
    for archive in "${tarballs[@]}"; do
      name=$(tar -xOf "$archive" package/package.json | jq -er '.name')
      add_dependency "$consumer" "$name" "file:$archive"
    done
    cd "$consumer"
    npm install --no-audit --no-fund --cache "$consumer/.npm-cache"
    import_dependencies
    return
  fi

  registry_specs "$(cd "$scripts_dir/.." && pwd)" "$version" > "$consumer/specs"
  specs=()
  while IFS= read -r spec; do
    specs+=("$spec")
  done < "$consumer/specs"
  for spec in "${specs[@]}"; do
    add_dependency "$consumer" "${spec%@*}" "$version"
  done
  cd "$consumer"
  # The user file, the global file and npm_config_* variables in any letter case are
  # emptied so none of them can steer this install. npm's builtin npmrc stays as
  # installed, and HTTP_PROXY and kin are left alone: a proxied runner needs them.
  # Two empty files: npm refuses to load one path as both the user and the global config.
  : > "$consumer/.npmrc"
  : > "$consumer/.npmrc-global"
  local -a scrub=()
  while IFS= read -r name; do scrub+=(-u "$name"); done < <(env | awk -F= 'tolower($1) ~ /^npm_config_/ {print $1}')
  # ${scrub[@]+...}: an empty array is "unbound" to bash 3.2 under set -u.
  if ! env ${scrub[@]+"${scrub[@]}"} npm install --no-audit --no-fund --registry "$registry" \
      --userconfig "$consumer/.npmrc" --globalconfig "$consumer/.npmrc-global" \
      --cache "$consumer/.npm-cache" > "$consumer/npm-install.log" 2>&1; then
    cat "$consumer/npm-install.log" >&2
    for spec in "${specs[@]}"; do
      if grep -qF -- "${spec%@*}" "$consumer/npm-install.log"; then
        echo "ERROR: $spec did not install from $registry (npm's error above)" >&2
      fi
    done
    exit 1
  fi
  cat "$consumer/npm-install.log"
  import_dependencies
  assert_lockfile_versions "$consumer/package-lock.json" "$version" "${#specs[@]}"
}

main "$@"
