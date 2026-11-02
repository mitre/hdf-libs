#!/usr/bin/env bash
# Characterize the shared formal/snapshot consumer check with real npm installs.
set -euo pipefail
checker="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/check-npm-consumers.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/package" "$work/archives" "$work/empty"
printf '{"name":"@mitre/hdf-smoke-test","version":"0.0.0","type":"module","main":"index.js"}\n' > "$work/package/package.json"
printf 'export const ok = true;\n' > "$work/package/index.js"
tar -czf "$work/archives/test.tgz" -C "$work" package
bash "$checker" "$work/archives" > "$work/result.log" 2>&1
grep -qF 'Imported @mitre/hdf-smoke-test' "$work/result.log"
echo 'ok: valid packed package imports outside the workspace'

printf 'throw new Error("intentional-broken-import");\n' > "$work/package/index.js"
tar -czf "$work/archives/test.tgz" -C "$work" package
if bash "$checker" "$work/archives" > "$work/result.log" 2>&1; then
  echo 'FAIL: broken packed import was accepted' >&2
  exit 1
fi
grep -qF 'intentional-broken-import' "$work/result.log"
echo 'ok: broken packed import fails'

if bash "$checker" "$work/empty" > "$work/result.log" 2>&1; then
  echo 'FAIL: empty publication batch was accepted' >&2
  exit 1
fi
grep -qF 'No package tarballs' "$work/result.log"
echo 'ok: empty publication batch fails'
