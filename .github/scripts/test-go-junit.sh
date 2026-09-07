#!/bin/bash
# Per-module Go tests through gotestsum, so every run leaves a JUnit record for
# the test gate to convert. Filenames carry the OS so both matrix legs can
# share one artifact directory.
#
# Test failures fail THIS script: the test job stays the failure authority,
# and the gate is the uniform evidence bundle plus the policy point for what
# an exit code cannot express (see .github/hdf-thresholds/tests.yaml).
#
# GO_COVERAGE=1 (the ubuntu leg) also writes per-module coverage profiles,
# absorbing what used to be a separate coverage job.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
OS_TAG="${OS_TAG:?set OS_TAG (e.g. ubuntu-latest)}"
OUT="$PWD/test-artifacts"
mkdir -p "$OUT"

go install "gotest.tools/gotestsum@${GOTESTSUM_VERSION:?set GOTESTSUM_VERSION}"
# By full path: GOPATH/bin is not reliably on PATH under git-bash on windows.
GOTESTSUM="$(go env GOPATH)/bin/gotestsum"

FAIL=0
for dir in $(go work edit -json | jq -r '.Use[].DiskPath' | tr -d '\r'); do
  junit="$OUT/go-$(echo "${dir#./}" | tr '/' '-')-$OS_TAG.xml"
  rc=0
  if [ "${GO_COVERAGE:-}" = "1" ]; then
    (cd "$dir" && "$GOTESTSUM" --junitfile "$junit" -- -coverprofile=coverage.out ./...) || rc=$?
    (cd "$dir" && go tool cover -func=coverage.out | tail -1) || true
  else
    (cd "$dir" && "$GOTESTSUM" --junitfile "$junit" -- ./...) || rc=$?
  fi
  [ "$rc" -eq 0 ] || FAIL=1
  # gotestsum can exit nonzero without writing the file at all; the gate would
  # then never see this module.
  if ! test -s "$junit"; then
    echo "::error::missing JUnit output for $dir"
    FAIL=1
  fi
done
exit $FAIL
