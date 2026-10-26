#!/usr/bin/env bash
# Install and import packed packages outside the workspace, as an npm consumer.
set -euo pipefail

if [ "$#" -ne 1 ] || [ ! -d "$1" ]; then
  echo "usage: $0 <directory containing package tarballs>" >&2
  exit 2
fi
archives=$(cd "$1" && pwd)
shopt -s nullglob
tarballs=("$archives"/*.tgz)
if [ "${#tarballs[@]}" -eq 0 ]; then
  echo 'No package tarballs to check' >&2
  exit 1
fi
consumer=$(mktemp -d)
trap 'rm -rf "$consumer"' EXIT
printf '{"private":true,"type":"module","dependencies":{}}\n' > "$consumer/package.json"
for archive in "${tarballs[@]}"; do
  name=$(tar -xOf "$archive" package/package.json | jq -er '.name')
  jq --arg name "$name" --arg archive "file:$archive" '.dependencies[$name] = $archive' \
    "$consumer/package.json" > "$consumer/manifest.json"
  mv "$consumer/manifest.json" "$consumer/package.json"
done
cd "$consumer"
npm install --no-audit --no-fund --cache "$consumer/.npm-cache"
node --input-type=module -e 'import fs from "node:fs"; for (const name of Object.keys(JSON.parse(fs.readFileSync("package.json")).dependencies)) { await import(name); console.log("Imported", name); }'
