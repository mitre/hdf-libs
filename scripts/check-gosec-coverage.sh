#!/usr/bin/env bash
#
# Fails if any module in go.work would be linted without gosec.
#
# gosec has no standalone CI step: it runs as a linter inside golangci-lint,
# which means a module is scanned only if golangci-lint resolves a config that
# enables it. golangci-lint searches the module directory and then each parent,
# so one config at the repository root covers every module that does not
# override it — and a NEW module inherits that coverage with no second edit.
#
# That is the property this script defends. Four modules (hdf-engine/go,
# hdf-fixtures, hdf-schema/dist/go, hdf-schema/testhdf/go) were silently
# unscanned because they carried no config and none was inherited, while
# golangci-lint and govulncheck already enumerated go.work and picked them up.
#
# THIS SCRIPT FAILS CLOSED. It asserts, per module:
#   - a config file actually resolves (an unconfigured module falls back to
#     golangci-lint's defaults, which do NOT include gosec, and says so only in
#     a warning nobody reads);
#   - the RESOLVED PATH is reported, because nearest-wins means a stray config
#     between a module and the root would silently take precedence;
#   - gosec appears in that config's enabled set.
# It also asserts it checked N of N modules, so a parsing failure cannot look
# like a clean run.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Preflight every tool before using it. Without this, a missing `go` or `jq`
# leaves the pipeline below empty and the run dies reporting "go.work lists no
# modules" — a false diagnosis of the repository rather than of the machine.
for tool in go jq golangci-lint; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is not on PATH; cannot verify gosec coverage" >&2
    exit 1
  fi
done

# Enumerated in two steps on purpose: a pipeline reports only the LAST command's
# status, so `go work edit -json | jq` would swallow a failure of `go` itself.
if ! workspace_json="$(go work edit -json 2>&1)"; then
  echo "error: could not read go.work:" >&2
  printf '%s\n' "$workspace_json" | sed 's/^/    /' >&2
  exit 1
fi

if ! modules="$(printf '%s' "$workspace_json" | jq -r '.Use[].DiskPath' 2>&1)"; then
  echo "error: could not parse the go.work module list:" >&2
  printf '%s\n' "$modules" | sed 's/^/    /' >&2
  exit 1
fi

if [ -z "$modules" ]; then
  echo "error: go.work lists no modules" >&2
  exit 1
fi

declared="$(printf '%s\n' "$modules" | grep -c .)"
checked=0
failed=0

for dir in $modules; do
  dir="${dir#./}"

  if ! config_path="$(cd "$dir" && golangci-lint config path 2>&1)" || \
     [ -z "$config_path" ] || \
     printf '%s' "$config_path" | grep -qi 'no config file'; then
    echo "FAIL $dir — no golangci-lint config resolves, so it is linted with"
    echo "     defaults, and gosec is not a default linter."
    failed=1
    checked=$((checked + 1))
    continue
  fi

  enabled="$(cd "$dir" && golangci-lint linters 2>/dev/null |
    awk '/Enabled by your configuration/{f=1;next} /Disabled by your configuration/{f=0} f && NF' |
    cut -d: -f1)"

  if [ -z "$enabled" ]; then
    echo "FAIL $dir — could not read the enabled-linter set; refusing to report a pass"
    failed=1
    checked=$((checked + 1))
    continue
  fi

  if printf '%s\n' "$enabled" | grep -qx 'gosec'; then
    printf 'ok   %-24s gosec via %s\n' "$dir" "$config_path"
  else
    echo "FAIL $dir — config $config_path does not enable gosec"
    failed=1
  fi
  checked=$((checked + 1))
done

if [ "$checked" -ne "$declared" ]; then
  echo "error: checked $checked of $declared go.work modules — one was skipped" >&2
  exit 1
fi
echo "checked $checked of $declared modules"

if [ "$failed" -ne 0 ]; then
  cat >&2 <<'MSG'

Add the linter config at the REPOSITORY ROOT rather than copying one into the
module: golangci-lint walks up from the module directory, so a root config
covers every module that does not deliberately override it, and the next module
someone adds inherits it automatically. Copying a config per module is what let
these four drift out of coverage in the first place.
MSG
  exit 1
fi
