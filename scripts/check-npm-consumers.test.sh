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

# Registry mode. Only the last case reaches registry.npmjs.org; the others run
# the checker against a stub npm that records its call, writes an importable
# stub for every dependency the checker asked for, and drops in a fixture lockfile.
repo="$(cd "$(dirname "$checker")/.." && pwd)"
snapshot='3.8.0-next.1.1'
mkdir -p "$work/bin"
cat > "$work/bin/npm" <<'NPM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$@" > "$STUB_NPM_ARGS"
env | grep -i '^npm_config_' > "$STUB_NPM_ENV" || true
pwd > "$STUB_NPM_CWD"
cp package.json "$STUB_NPM_MANIFEST"
jq -r '.dependencies | keys[]' package.json | while IFS= read -r name; do
  mkdir -p "node_modules/$name"
  printf '{"name":"%s","type":"module","main":"index.js"}\n' "$name" > "node_modules/$name/package.json"
  echo 'export const ok = true;' > "node_modules/$name/index.js"
done
cp "$STUB_NPM_LOCK" package-lock.json
NPM
chmod +x "$work/bin/npm"
export STUB_NPM_ARGS="$work/npm-args" STUB_NPM_CWD="$work/npm-cwd" STUB_NPM_MANIFEST="$work/npm-manifest.json" STUB_NPM_ENV="$work/npm-env"
# The consistent lockfile carries one entry per inventory package, built from the inventory
# itself, so its count is the count the checker must see; the hand-written two-entry file
# below is the SHORT case.
inventory_names=$(bash "$repo/scripts/list-npm-packages.sh" "$repo" | while IFS= read -r pkg; do jq -r .name "$repo/$pkg/package.json"; done)
printf '%s\n' "$inventory_names" | jq -R -s --arg v "$snapshot" '
  (split("\n") | map(select(length > 0))) as $names
  | {name: "consumer", lockfileVersion: 3,
     packages: ({"": {dependencies: ($names | map({key: ., value: $v}) | from_entries)}}
       + ($names | map({key: ("node_modules/" + .), value: {version: $v}}) | from_entries)
       + {"node_modules/ajv": {version: "8.17.1"}})}' > "$work/consistent-lock.json"
cat > "$work/short-lock.json" <<LOCK
{"name":"consumer","lockfileVersion":3,"packages":{
  "":{"dependencies":{"@mitre/hdf-converters":"$snapshot","@mitre/hdf-schema":"$snapshot"}},
  "node_modules/@mitre/hdf-converters":{"version":"$snapshot"},
  "node_modules/@mitre/hdf-schema":{"version":"$snapshot"},
  "node_modules/ajv":{"version":"8.17.1"}}}
LOCK
cat > "$work/mixed-lock.json" <<LOCK
{"name":"consumer","lockfileVersion":3,"packages":{
  "":{"dependencies":{"@mitre/hdf-converters":"$snapshot","@mitre/hdf-schema":"$snapshot"}},
  "node_modules/@mitre/hdf-converters":{"version":"$snapshot"},
  "node_modules/@mitre/hdf-converters/node_modules/@mitre/hdf-schema":{"version":"3.8.0-next.0.1"},
  "node_modules/@mitre/hdf-schema":{"version":"$snapshot"},
  "node_modules/ajv":{"version":"8.17.1"}}}
LOCK

if STUB_NPM_LOCK="$work/mixed-lock.json" PATH="$work/bin:$PATH" bash "$checker" --registry-version "$snapshot" > "$work/result.log" 2>&1; then
  echo 'FAIL: lockfile with a sibling at another version was accepted' >&2
  exit 1
fi
grep -qF 'Imported @mitre/hdf-' "$work/result.log"
grep -qF '@mitre/hdf-schema' "$work/result.log"
grep -qF '3.8.0-next.0.1' "$work/result.log"
grep -qF "$snapshot" "$work/result.log"
test "$(grep -c '^ERROR' "$work/result.log")" -eq 1
echo 'ok: lockfile with a sibling at another version fails naming it and both versions'

STUB_NPM_LOCK="$work/consistent-lock.json" PATH="$work/bin:$PATH" bash "$checker" --registry-version "$snapshot" > "$work/result.log" 2>&1
inventory_count=$(printf '%s\n' "$inventory_names" | grep -c .)
grep -qF "Every @mitre package in package-lock.json ($inventory_count) is $snapshot" "$work/result.log"
echo 'ok: lockfile with every sibling at the snapshot version passes and reports the inventory count'

if STUB_NPM_LOCK="$work/short-lock.json" PATH="$work/bin:$PATH" bash "$checker" --registry-version "$snapshot" > "$work/result.log" 2>&1; then
  echo 'FAIL: a lockfile holding fewer @mitre packages than requested was accepted' >&2
  exit 1
fi
grep -qF "holds 2 @mitre packages, but $inventory_count were requested" "$work/result.log"
echo 'ok: a lockfile resolving fewer @mitre packages than requested fails naming both counts'

bash "$repo/scripts/list-npm-packages.sh" "$repo" | while IFS= read -r dir; do
  printf '%s@%s\n' "$(jq -er .name "$repo/$dir/package.json")" "$snapshot"
done | sort > "$work/expected-specs"
jq -r '.dependencies | to_entries[] | "\(.key)@\(.value)"' "$STUB_NPM_MANIFEST" | sort | diff "$work/expected-specs" -
test "$(grep -c '^Imported @mitre/hdf-' "$work/result.log")" -eq "$(wc -l < "$work/expected-specs")"
echo 'ok: every inventory package is requested by name at the snapshot version and imported once'

grep -qxF 'install' "$work/npm-args"
grep -qxF -- '--no-audit' "$work/npm-args"
grep -qxF -- '--no-fund' "$work/npm-args"
grep -A1 -xF -- '--registry' "$work/npm-args" | grep -qxF 'https://registry.npmjs.org/'
consumer="$(cat "$work/npm-cwd")"
case "$consumer" in "$repo"/*) echo "FAIL: consumer $consumer is inside the checkout" >&2; exit 1 ;; esac
grep -A1 -xF -- '--cache' "$work/npm-args" | tail -1 | grep -q "^$consumer/"
echo 'ok: install runs against registry.npmjs.org from a consumer outside the checkout with its own cache'

grep -A1 -xF -- '--userconfig' "$work/npm-args" | tail -1 | grep -q "^$consumer/"
grep -A1 -xF -- '--globalconfig' "$work/npm-args" | tail -1 | grep -q "^$consumer/"
echo 'ok: npm is given a fresh user and a fresh global config, both under the consumer directory'

# npm matches the npm_config_ prefix case-insensitively, so both spellings must be scrubbed.
env 'NPM_CONFIG_@mitre:registry=http://127.0.0.1:9/' 'npm_config_proxy=http://127.0.0.1:9/' STUB_NPM_LOCK="$work/consistent-lock.json" \
  PATH="$work/bin:$PATH" bash "$checker" --registry-version "$snapshot" > "$work/result.log" 2>&1
test ! -s "$work/npm-env"
echo 'ok: npm_config_* variables of either case never reach npm'

if bash "$checker" --registry-version > "$work/result.log" 2>&1; then
  echo 'FAIL: registry mode without a version was accepted' >&2
  exit 1
fi
grep -qF 'usage:' "$work/result.log"
echo 'ok: registry mode without a version fails with usage'

# ONLINE: the one case that reaches registry.npmjs.org, with a version nothing publishes.
if bash "$checker" --registry-version 0.0.0-nonexistent > "$work/result.log" 2>&1; then
  echo 'FAIL: a version absent from the registry was accepted' >&2
  exit 1
fi
grep -qE '@mitre/hdf-[a-z-]+@0\.0\.0-nonexistent' "$work/result.log"
grep -qF 'npm error' "$work/result.log"
echo 'ok (online): a version absent from the registry fails naming the package with npm'"'"'s error'
