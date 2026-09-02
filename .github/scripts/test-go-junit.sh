#!/bin/bash
# Per-module Go tests through gotestsum so every run leaves a JUnit record
# for the test gate. Test failures fail THIS script — the test job stays the
# failure authority; gate-hdf-tests is the uniform evidence bundle and the
# policy point for what exit codes can't express. Runs under bash on both
# ubuntu and windows runners (git-bash ships jq).
# GO_COVERAGE=1 (the ubuntu matrix leg) adds per-module coverage profiles,
# absorbing the former dedicated coverage job's Go half.
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel)}"
OUT="${TEST_DIR:-$ROOT/test-artifacts}"
OS_TAG="${OS_TAG:?set OS_TAG (e.g. ubuntu-latest)}"
GOTESTSUM_VERSION="${GOTESTSUM_VERSION:?set GOTESTSUM_VERSION}"

go install "gotest.tools/gotestsum@${GOTESTSUM_VERSION}"

mkdir -p "$OUT"
cd "$ROOT"
FAIL=0
for dir in $(go work edit -json | jq -r '.Use[].DiskPath'); do
  name=$(echo "${dir#./}" | tr '/' '-')
  junit="$OUT/go-$name.xml"
  echo "::group::go test $dir"
  rc=0
  if [ "${GO_COVERAGE:-}" = "1" ]; then
    (cd "$dir" && gotestsum --junitfile "$junit" -- -coverprofile=coverage.out ./...) || rc=$?
    (cd "$dir" && test -f coverage.out && go tool cover -func=coverage.out | tail -1) || true
  else
    (cd "$dir" && gotestsum --junitfile "$junit" -- ./...) || rc=$?
  fi
  echo "::endgroup::"
  [ "$rc" -ne 0 ] && FAIL=1
  if ! test -s "$junit"; then
    echo "::error::missing JUnit output for $dir"
    FAIL=1
  else
    echo "go-$name.xml" >> "$OUT/manifest-tests-go-$OS_TAG.txt"
  fi
done
exit $FAIL
