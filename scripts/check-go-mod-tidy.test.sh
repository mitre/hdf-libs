#!/usr/bin/env bash
#
# Pins check-go-mod-tidy.sh: a tidy module passes, an untidy one fails naming
# it, a sibling require at the zero pseudo-version fails naming it, and the
# script writes nothing. Fixtures are throwaway modules in a temp dir with
# GOPROXY=off, so the test needs no network: a stray go.sum line, an unused
# require of a module already in the local cache, and a replace to a local
# directory are each enough to make the toolchain speak.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/check-go-mod-tidy.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GOPROXY=off

pass=0
fail=0

check() {
  local name="$1" want_exit="$2" dir="$3"
  local got_exit=0
  "$SCRIPT" "$dir" >"$work/out" 2>&1 || got_exit=$?
  if [ "$got_exit" -eq "$want_exit" ]; then
    pass=$((pass + 1))
    echo "ok   $name (exit $got_exit)"
  else
    fail=$((fail + 1))
    echo "FAIL $name — wanted exit $want_exit, got $got_exit"
    sed 's/^/       /' "$work/out"
  fi
}

# A workspace of two tidy modules passes.
mkdir -p "$work/tidy/a" "$work/tidy/b"
printf 'module example.com/a\n\ngo 1.26.9\n' > "$work/tidy/a/go.mod"
printf 'package a\n' > "$work/tidy/a/a.go"
printf 'module example.com/b\n\ngo 1.26.9\n' > "$work/tidy/b/go.mod"
printf 'package b\n' > "$work/tidy/b/b.go"
printf 'go 1.26.9\n\nuse (\n\t./a\n\t./b\n)\n' > "$work/tidy/go.work"
check "passes a workspace whose modules are tidy" 0 "$work/tidy"

# A stray go.sum line is what a version bump leaves behind.
mkdir -p "$work/stray/a"
printf 'module example.com/a\n\ngo 1.26.9\n' > "$work/stray/a/go.mod"
printf 'package a\n' > "$work/stray/a/a.go"
printf 'github.com/example/unused v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$work/stray/a/go.sum"
printf 'go 1.26.9\n\nuse ./a\n' > "$work/stray/go.work"
check "refuses a module with a stray go.sum line" 1 "$work/stray"
if grep -q '^UNTIDY ./a' "$work/out"; then
  pass=$((pass + 1)); echo "ok   names the untidy module"
else
  fail=$((fail + 1)); echo "FAIL did not name the untidy module; output was:"; sed 's/^/       /' "$work/out"
fi
if grep -q 'github.com/example/unused' "$work/stray/a/go.sum"; then
  pass=$((pass + 1)); echo "ok   writes nothing"
else
  fail=$((fail + 1)); echo "FAIL the check rewrote go.sum"
fi

# An unused require, the other shape tidy removes. testify is in every
# developer's cache here, so this stays offline.
mkdir -p "$work/unused/a"
printf 'module example.com/a\n\ngo 1.26.9\n\nrequire github.com/stretchr/testify v1.12.1\n' > "$work/unused/a/go.mod"
printf 'package a\n' > "$work/unused/a/a.go"
printf 'go 1.26.9\n\nuse ./a\n' > "$work/unused/go.work"
check "refuses a module with an unused require" 1 "$work/unused"

# One untidy module among tidy ones is still a failure that names only it.
mkdir -p "$work/mixed/a" "$work/mixed/b"
printf 'module example.com/a\n\ngo 1.26.9\n' > "$work/mixed/a/go.mod"
printf 'package a\n' > "$work/mixed/a/a.go"
printf 'module example.com/b\n\ngo 1.26.9\n' > "$work/mixed/b/go.mod"
printf 'package b\n' > "$work/mixed/b/b.go"
printf 'github.com/example/unused v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' > "$work/mixed/b/go.sum"
printf 'go 1.26.9\n\nuse (\n\t./a\n\t./b\n)\n' > "$work/mixed/go.work"
check "names only the untidy module in a mixed workspace" 1 "$work/mixed"
if grep -q '^UNTIDY ./b' "$work/out" && ! grep -q '^UNTIDY ./a' "$work/out"; then
  pass=$((pass + 1)); echo "ok   reports b and not a"
else
  fail=$((fail + 1)); echo "FAIL wrong module named; output was:"; sed 's/^/       /' "$work/out"
fi

# A sibling require at the zero pseudo-version is tidy to Go — the replace
# makes it resolvable — and is exactly what a downgrading `go get` followed by
# tidy leaves behind: a module that no release can publish.
mkdir -p "$work/unpinned/a" "$work/unpinned/sib"
printf 'module github.com/mitre/hdf-libs/sib/v3\n\ngo 1.26.9\n' > "$work/unpinned/sib/go.mod"
printf 'package sib\n' > "$work/unpinned/sib/sib.go"
printf 'module example.com/a\n\ngo 1.26.9\n\nrequire github.com/mitre/hdf-libs/sib/v3 v3.0.0-00010101000000-000000000000\n\nreplace github.com/mitre/hdf-libs/sib/v3 => ../sib\n' > "$work/unpinned/a/go.mod"
printf 'package a\n\nimport _ "github.com/mitre/hdf-libs/sib/v3"\n' > "$work/unpinned/a/a.go"
printf 'go 1.26.9\n\nuse (\n\t./a\n\t./sib\n)\n' > "$work/unpinned/go.work"
check "refuses a sibling require at the zero pseudo-version" 1 "$work/unpinned"
if grep -q '^UNPINNED ./a: github.com/mitre/hdf-libs/sib/v3' "$work/out"; then
  pass=$((pass + 1)); echo "ok   names the module and the unpinned sibling"
else
  fail=$((fail + 1)); echo "FAIL did not name the unpinned sibling; output was:"; sed 's/^/       /' "$work/out"
fi

# A root with no go.work is a mistake, not a pass.
mkdir -p "$work/nowork"
check "refuses a root without go.work" 1 "$work/nowork"

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
