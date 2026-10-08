#!/usr/bin/env bash
#
# Pins check-release-version.sh.
#
# The bug it guards shipped: v3.7.0's assets were named 3.7.0-rc.1 because
# goreleaser resolved the version from `git describe` when the stable tag and
# its rc shared a commit. The GORELEASER_CURRENT_TAG pin fixes the choice, but
# nothing asserted the outcome — so the cases below are the mismatch that must
# fail (naming BOTH values, or the operator cannot tell which side is wrong)
# and the fail-closed cases, because an unreadable metadata.json proving
# nothing must not read as agreement.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CHECKER="$script_dir/check-release-version.sh"

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is not on PATH; cannot exercise the release-version check" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

report() {
  local label="$1" ok="$2" detail="${3:-}"
  if [ "$ok" -eq 0 ]; then
    echo "ok   $label"
    pass=$((pass + 1))
  else
    echo "FAIL $label${detail:+ — $detail}"
    fail=$((fail + 1))
  fi
}

# A dist/metadata.json carrying only the fields the checker reads. The real file
# has more; goreleaser's own answer for the build version is .version.
make_metadata() {
  local dir="$1" version="$2"
  mkdir -p "$dir"
  jq -n --arg v "$version" '{project_name:"hdf", version:$v, tag:("v"+$v)}' > "$dir/metadata.json"
}

# run <tag> <metadata-path> -> captures exit code in rc and output in out
run() {
  out="$(GITHUB_REF_NAME="$1" "$CHECKER" "$2" 2>&1)"
  rc=$?
}

# --- the shipped bug: rc metadata under a stable tag must fail ---------------
make_metadata "$work/mismatch/dist" "3.7.0-rc.1"
run v3.7.0 "$work/mismatch/dist/metadata.json"
if [ "$rc" -ne 0 ] &&
  printf '%s' "$out" | grep -q '3\.7\.0-rc\.1' &&
  printf '%s' "$out" | grep -q 'v3\.7\.0'; then
  report "a stable tag over rc-named metadata fails, naming both values" 0
else
  report "a stable tag over rc-named metadata fails, naming both values" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /' | head -5
fi

# --- the matching case must pass, or the check blocks every release ---------
make_metadata "$work/match/dist" "3.7.1"
run v3.7.1 "$work/match/dist/metadata.json"
if [ "$rc" -eq 0 ]; then
  report "a stable tag matching its metadata passes" 0
else
  report "a stable tag matching its metadata passes" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /' | head -5
fi

# --- an rc release is a legitimate release, not a mismatch ------------------
make_metadata "$work/rc/dist" "3.8.0-rc.2"
run v3.8.0-rc.2 "$work/rc/dist/metadata.json"
if [ "$rc" -eq 0 ]; then
  report "an rc tag matching its metadata passes" 0
else
  report "an rc tag matching its metadata passes" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /' | head -5
fi

# --- only the leading v is stripped; the rest must match exactly ------------
make_metadata "$work/prefix/dist" "3.7.10"
run v3.7.1 "$work/prefix/dist/metadata.json"
if [ "$rc" -ne 0 ]; then
  report "a prefix match is not a match" 0
else
  report "a prefix match is not a match" 1 "exit 0 on 3.7.10 vs v3.7.1"
fi

# --- fail closed: nothing to read is not agreement -------------------------
run v3.7.1 "$work/absent/dist/metadata.json"
if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -qi 'metadata'; then
  report "a missing metadata.json fails closed" 0
else
  report "a missing metadata.json fails closed" 1 "exit $rc"
  printf '%s\n' "$out" | sed 's/^/       /' | head -5
fi

mkdir -p "$work/noversion/dist"
jq -n '{project_name:"hdf"}' > "$work/noversion/dist/metadata.json"
run v3.7.1 "$work/noversion/dist/metadata.json"
if [ "$rc" -ne 0 ]; then
  report "a metadata.json without .version fails closed" 0
else
  report "a metadata.json without .version fails closed" 1 "exit 0"
fi

# --- fail closed: no tag in the environment --------------------------------
make_metadata "$work/notag/dist" "3.7.1"
out="$(env -u GITHUB_REF_NAME "$CHECKER" "$work/notag/dist/metadata.json" 2>&1)"
rc=$?
if [ "$rc" -ne 0 ]; then
  report "an unset GITHUB_REF_NAME fails closed" 0
else
  report "an unset GITHUB_REF_NAME fails closed" 1 "exit 0"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
