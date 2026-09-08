#!/usr/bin/env bash
#
# Pins check-go-module-consumers.sh against the ways it has actually failed.
#
# That script exists to stop a class of silent breakage, and three successive
# versions of it reported `ok` while the bug was present: it swallowed a failing
# `go list`, it matched on a version signature a wrong pin evaded, and its
# GO_MODULES parse dropped entries whose quoting it did not anticipate — with a
# count guard that shared the same blind spot. Every case below is one of those,
# so a regression announces itself instead of going quiet.
#
# Fixtures are throwaway modules in a temp dir with a fake release.yml, so the
# test never touches the repo and never needs the network.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CHECKER="$script_dir/check-go-module-consumers.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

# Builds a fixture repo and returns its path. $1 is the GO_MODULES array body,
# already formatted as the workflow indents it.
make_fixture() {
  local name="$1" modules_body="$2"
  local root="$work/$name"
  mkdir -p "$root/.github/workflows" "$root/scripts"
  cp "$CHECKER" "$root/scripts/"
  cat > "$root/.github/workflows/release.yml" <<YAML
jobs:
  release:
    steps:
      - run: |
          GO_MODULES=(
$modules_body
          )
YAML
  printf '%s' "$root"
}

# Writes a minimal module at $1 with module path $2 and one importable package.
make_module() {
  local dir="$1" path="$2" extra_import="${3:-}"
  mkdir -p "$dir"
  cat > "$dir/go.mod" <<EOF
module $path

go 1.26.6
EOF
  # The conditional must not be the group's last statement: under `set -e` a
  # false test would abort the whole run.
  {
    echo "package lib"
    if [ -n "$extra_import" ]; then
      echo "import _ \"$extra_import\""
    fi
  } > "$dir/lib.go"
}

expect() {
  local label="$1" want="$2" root="$3"
  local got=0
  ( cd "$root" && ./scripts/check-go-module-consumers.sh ) > "$work/out.log" 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then
    echo "ok   $label"
    pass=$((pass + 1))
  else
    echo "FAIL $label — expected exit $want, got $got"
    sed 's/^/       /' "$work/out.log"
    fail=$((fail + 1))
  fi
}

# --- a clean fixture passes, so a later failure means something real --------
root="$(make_fixture clean '            "liba"
            "libb"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
make_module "$root/libb" "example.com/fixture/libb/v3"
expect "clean fixture passes" 0 "$root"

# --- an entry the old regex parse dropped must still be CHECKED -------------
# Single quotes are legal bash and legal YAML; the regex saw nothing, and the
# count guard agreed because it derived both counts from the same parse.
#
# The bug is planted BEHIND the single-quoted entry deliberately. Asserting a
# clean fixture still exits 0 would prove nothing: a dropped module also exits
# 0. Only a module that is actually examined can report its offender.
root="$(make_fixture requoted '            "liba"
            '"'"'libb'"'"'')"
make_module "$root/liba" "example.com/fixture/liba/v3"
make_module "$root/libb" "example.com/fixture/libb/v3" "example.com/fixture/untagged"
make_module "$root/untagged" "example.com/fixture/untagged"
expect "an unusually quoted entry is still checked, not just parsed" 1 "$root"

# --- a module listed but missing on disk is an error, not a skip ------------
root="$(make_fixture missing '            "liba"
            "gone"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
expect "a listed module with no go.mod errors" 1 "$root"

# --- a broken go list must fail, never pass ---------------------------------
root="$(make_fixture broken '            "liba"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
echo 'package lib
import _ "example.invalid/nope"' > "$root/liba/broken.go"
expect "an unresolvable import fails rather than passing" 1 "$root"

# --- a go list failure on ONE platform must fail, even though others succeed -
# The previous case is also caught by the empty-package guard, so it cannot tell
# whether the go list error path works. Here the module lists fine on linux, so
# package_count is non-zero and only the error path can catch the windows break.
root="$(make_fixture partialbreak '            "liba"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
printf '//go:build windows\n\npackage lib\n\nimport _ "example.invalid/nope"\n' > "$root/liba/win.go"
expect "a go list failure on one platform is not masked by another" 1 "$root"

# --- a `go list ./...` failure is distinct from a `-deps` failure ----------
# The case above breaks dependency resolution; this one breaks package listing
# (two package names in one directory). They are separate error paths in the
# checker and a mutation to one does not exercise the other.
# Constrained to windows so linux still lists packages successfully; otherwise
# the empty-package guard catches it and this case cannot tell whether the
# listing error path works.
root="$(make_fixture unlistable '            "liba"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
printf '//go:build windows\n\npackage different\n' > "$root/liba/conflict.go"
expect "a module whose packages cannot be listed fails" 1 "$root"

# --- progress output must never be mistaken for a package path --------------
# `go` writes "go: downloading ..." to stderr. An earlier version captured it
# with 2>&1 and passed those words to `go list -deps` as package arguments —
# invisible on a warm cache, a false FAIL on CI's cold one. The package-path
# filter is what stops it, so exercise the filter directly: a warm local cache
# cannot reproduce the condition.
progress_input="$(printf 'example.com/fixture/liba/v3\ngo: downloading example.com/dep v1.1.0\nexample.com/fixture/liba/v3/internal/x\n')"
filtered="$(printf '%s\n' "$progress_input" | grep -E '^[^[:space:]:]+$' | grep -v '/internal/' || true)"
if [ "$filtered" = "example.com/fixture/liba/v3" ]; then
  echo "ok   progress lines are not mistaken for package paths"
  pass=$((pass + 1))
else
  echo "FAIL progress lines are not mistaken for package paths — got: $filtered"
  fail=$((fail + 1))
fi

# --- a module whose only packages are internal/ must not read as a pass -----
root="$(make_fixture internalonly '            "liba"')"
mkdir -p "$root/liba/internal/only"
cat > "$root/liba/go.mod" <<'EOF'
module example.com/fixture/liba/v3

go 1.26.6
EOF
echo 'package only' > "$root/liba/internal/only/only.go"
expect "a module with only internal packages is not a pass" 1 "$root"

# --- listing a module whose path lacks the major suffix is not a fix --------
# This is the wrong turn the card names: adding the untagged module to
# GO_MODULES looks like it works, but the tag minted for it resolves for nobody.
root="$(make_fixture badmajor '            "liba"
            "helper"')"
make_module "$root/liba" "example.com/fixture/liba/v3"
make_module "$root/helper" "example.com/fixture/helper"
expect "a listed module missing the /vN suffix is rejected" 1 "$root"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
