#!/usr/bin/env bash
#
# Pins check-gosec-coverage.sh, and pins the property it depends on.
#
# The load-bearing claim of this card is about what happens when someone ADDS a
# module, so it is proven with a module actually added — a throwaway module in a
# temp workspace carrying a real gosec-detectable finding — never by inspecting
# config files. The negative case is what makes the positive one mean anything:
# with no root config the same finding goes unreported, which is precisely the
# state four real modules were in.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CHECKER="$script_dir/check-gosec-coverage.sh"
readonly LIBRARY_CONFIG="$script_dir/../.golangci.yml"

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

# A brand-new module: nested two levels deep, like hdf-engine/go, carrying a
# weak-hash finding (G401/G501). G304 and G104 are excluded by the shared
# config, so neither would prove anything.
make_workspace() {
  local root="$1" with_config="$2"
  mkdir -p "$root/newlib/go"
  cat > "$root/go.work" <<EOF
go 1.26.6

use ./newlib/go
EOF
  cat > "$root/newlib/go/go.mod" <<'EOF'
module example.com/newlib/go

go 1.26.6
EOF
  cat > "$root/newlib/go/lib.go" <<'EOF'
package newlib

import "crypto/md5"

// Fingerprint is deliberately weak so gosec has something to find.
func Fingerprint(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}
EOF
  if [ "$with_config" = "with-config" ]; then
    if [ ! -f "$LIBRARY_CONFIG" ]; then
      echo "error: shared config $LIBRARY_CONFIG does not exist; the fixtures would be meaningless" >&2
      exit 1
    fi
    cp "$LIBRARY_CONFIG" "$root/.golangci.yml"
  fi
  return 0
}

# --- the property: a new module inherits gosec from the root config ---------
root="$work/inherits"
make_workspace "$root" with-config
out="$(cd "$root/newlib/go" && golangci-lint run ./... 2>&1)"
if printf '%s' "$out" | grep -q 'gosec'; then
  report "a newly added module is scanned by gosec with no second edit" 0
else
  report "a newly added module is scanned by gosec with no second edit" 1 "no gosec finding reported"
  printf '%s\n' "$out" | sed 's/^/       /' | head -5
fi

# --- the negative control: without the root config the finding is missed ----
# This is the state hdf-engine/go was in. If this case ever reports a finding,
# the test above proves nothing, because gosec would be running anyway.
root="$work/uninherited"
make_workspace "$root" no-config
out="$(cd "$root/newlib/go" && golangci-lint run ./... 2>&1)"
if printf '%s' "$out" | grep -q 'gosec'; then
  report "without a root config the same finding goes unreported" 1 "gosec ran anyway; the positive case proves nothing"
else
  report "without a root config the same finding goes unreported" 0
fi

# --- the checker itself must FAIL on an uncovered workspace -----------------
root="$work/uncovered"
make_workspace "$root" no-config
mkdir -p "$root/scripts"
cp "$CHECKER" "$root/scripts/checker.sh"
( cd "$root" && ./scripts/checker.sh ) > "$work/uncovered.log" 2>&1
rc=$?
if [ "$rc" -ne 0 ] && grep -q 'no golangci-lint config resolves' "$work/uncovered.log"; then
  report "the checker fails on a workspace whose module has no config" 0
else
  report "the checker fails on a workspace whose module has no config" 1 "exit $rc"
  sed 's/^/       /' "$work/uncovered.log" | head -5
fi

# --- and PASS once the root config is there --------------------------------
root="$work/covered"
make_workspace "$root" with-config
mkdir -p "$root/scripts"
cp "$CHECKER" "$root/scripts/checker.sh"
( cd "$root" && ./scripts/checker.sh ) > "$work/covered.log" 2>&1
rc=$?
if [ "$rc" -eq 0 ] && grep -q 'checked 1 of 1 modules' "$work/covered.log"; then
  report "the checker passes once the root config covers the module" 0
else
  report "the checker passes once the root config covers the module" 1 "exit $rc"
  sed 's/^/       /' "$work/covered.log" | head -5
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
