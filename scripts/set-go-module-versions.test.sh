#!/usr/bin/env bash
#
# Pins set-go-module-versions.sh against the way it actually failed.
#
# Its header claims it fails closed. The first version did not: the helper that
# reads a module's requires ran inside a process substitution, where a failure
# is invisible to `set -e`. A malformed require produced a Python traceback on
# stderr, the verification loop then read zero lines, the straggler count stayed
# at zero, and the script printed success and exited 0 — having either left a
# pin unrewritten or written one Go itself rejects. The tag is published before
# anyone reads stderr, so "exits 0 with a traceback" is indistinguishable from
# "worked" at exactly the moment it matters.
#
# Fixtures are throwaway modules in a temp dir; this never touches the repo and
# never needs the network.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT="$script_dir/set-go-module-versions.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

pass=0
fail=0

check() {
  local name="$1" want_exit="$2" dir="$3" version="$4"
  local got_exit=0
  # shellcheck disable=SC2086 -- $version may carry a leading --check flag
  "$SCRIPT" $version "$dir" >"$work/out" 2>&1 || got_exit=$?
  if [ "$got_exit" -eq "$want_exit" ]; then
    pass=$((pass + 1))
    echo "ok   $name (exit $got_exit)"
  else
    fail=$((fail + 1))
    echo "FAIL $name — wanted exit $want_exit, got $got_exit"
    sed 's/^/       /' "$work/out"
  fi
}

# A require whose module path carries no major-version suffix cannot be pinned
# at v2+. Rewriting it anyway swaps one unresolvable pin for another, so the
# script must refuse rather than "succeed".
mkdir -p "$work/nosuffix"
cat > "$work/nosuffix/go.mod" <<'EOF'
module example.com/nosuffix

go 1.26.6

require github.com/mitre/hdf-libs/brand-new/go v0.0.0-00010101000000-000000000000
EOF
check "refuses a path that cannot carry the target major" 1 "$work/nosuffix" v3.7.0

# And it must leave the file alone when it refuses.
if grep -q 'v0.0.0-00010101000000-000000000000' "$work/nosuffix/go.mod"; then
  pass=$((pass + 1)); echo "ok   leaves the refused file untouched"
else
  fail=$((fail + 1)); echo "FAIL rewrote a require it had just refused"
fi

# `go mod edit -json` cannot parse a require whose version contradicts its path.
# The old script swallowed that and reported success.
mkdir -p "$work/unparseable"
cat > "$work/unparseable/go.mod" <<'EOF'
module example.com/unparseable

go 1.26.6

require github.com/mitre/hdf-libs/brand-new/go/v3 v0.0.0-00010101000000-000000000000
EOF
check "refuses a go.mod the toolchain cannot parse" 1 "$work/unparseable" v3.7.0

# A directory with nothing to rewrite is a mistake, not a no-op success: it
# usually means the caller pointed at the wrong root.
mkdir -p "$work/empty"
check "refuses a root containing no go.mod" 1 "$work/empty" v3.7.0

# A version that is not a Go version at all.
mkdir -p "$work/bare"
cat > "$work/bare/go.mod" <<'EOF'
module example.com/bare

go 1.26.6
EOF
check "refuses a version with no leading v" 1 "$work/bare" 3.7.0

# The happy path still works, and actually rewrites.
mkdir -p "$work/good"
cat > "$work/good/go.mod" <<'EOF'
module example.com/good

go 1.26.6

require (
	github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.5.1
	github.com/mitre/hdf-libs/hdf-validators/go/v3 v3.5.1 // indirect
	github.com/stretchr/testify v1.12.1
)
EOF
check "rewrites a well-formed tree" 0 "$work/good" v3.7.0

# Including the require carrying a trailing comment, which a regex-based first
# attempt silently skipped.
if [ "$(grep -c 'hdf-libs/[^ ]* v3\.7\.0' "$work/good/go.mod")" -eq 2 ]; then
  pass=$((pass + 1)); echo "ok   rewrites a require carrying a trailing comment"
else
  fail=$((fail + 1)); echo "FAIL missed a require; go.mod now:"; sed 's/^/       /' "$work/good/go.mod"
fi

# Third-party requires are none of its business.
if grep -q 'stretchr/testify v1.12.1' "$work/good/go.mod"; then
  pass=$((pass + 1)); echo "ok   leaves third-party requires alone"
else
  fail=$((fail + 1)); echo "FAIL rewrote a third-party require"
fi

# A nested checkout inside the root — an agent worktree under .claude/worktrees,
# a scratch clone — carries its own go.mod files, which belong to whatever branch
# that checkout has out, not to the release being prepared. Descending into one
# refused a real release over a go.mod the tag would never include.
mkdir -p "$work/nested/.claude/worktrees/stale"
cat > "$work/nested/go.mod" <<'EOF'
module example.com/nested

go 1.26.6

require github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.5.1
EOF
: > "$work/nested/.claude/worktrees/stale/.git"
cat > "$work/nested/.claude/worktrees/stale/go.mod" <<'EOF'
module example.com/stale

go 1.26.6

require github.com/mitre/hdf-libs/brand-new/go v0.0.0-00010101000000-000000000000
EOF
check "skips a nested checkout's go.mod" 0 "$work/nested" v3.7.0
if grep -q 'hdf-utilities/go/v3 v3.7.0' "$work/nested/go.mod" && grep -q 'v0.0.0-00010101000000-000000000000' "$work/nested/.claude/worktrees/stale/go.mod"; then
  pass=$((pass + 1)); echo "ok   rewrites the root and leaves the nested checkout alone"
else
  fail=$((fail + 1)); echo "FAIL touched the nested checkout or missed the root"
fi

# --check verifies without rewriting: the release workflow runs it on the tagged
# commit before anything publishes, so a tag pushed onto the wrong commit fails
# the run instead of publishing modules whose requires no tag provides.
mkdir -p "$work/checkgood"
cat > "$work/checkgood/go.mod" <<'EOF'
module example.com/checkgood

go 1.26.6

require (
	github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.7.2
	github.com/stretchr/testify v1.12.1
)
EOF
check "--check passes a tree already at the version" 0 "$work/checkgood" "--check v3.7.2"
mkdir -p "$work/checkbad"
cat > "$work/checkbad/go.mod" <<'EOF'
module example.com/checkbad

go 1.26.6

require github.com/mitre/hdf-libs/hdf-utilities/go/v3 v3.7.2
EOF
check "--check refuses a tree whose requires name another version" 1 "$work/checkbad" "--check v3.7.2-rc.2"
if grep -q 'hdf-utilities/go/v3 v3.7.2$' "$work/checkbad/go.mod"; then
  pass=$((pass + 1)); echo "ok   --check rewrites nothing"
else
  fail=$((fail + 1)); echo "FAIL --check rewrote a require; go.mod now:"; sed 's/^/       /' "$work/checkbad/go.mod"
fi
if grep -qE 'go.mod:5: github.com/mitre/hdf-libs/hdf-utilities/go/v3 is at v3.7.2, wanted v3.7.2-rc.2' "$work/out"; then
  pass=$((pass + 1)); echo "ok   --check names the file, the line, the require and both versions"
else
  fail=$((fail + 1)); echo "FAIL --check did not name the offending require; output was:"; sed 's/^/       /' "$work/out"
fi

# --check fails closed on a go.mod the toolchain cannot parse, exactly as the
# rewrite does: proving nothing is not the same as passing.
mkdir -p "$work/checkunparseable"
cat > "$work/checkunparseable/go.mod" <<'EOF'
module example.com/checkunparseable

go 1.26.6

require github.com/mitre/hdf-libs/brand-new/go/v3 v0.0.0-00010101000000-000000000000
EOF
check "--check refuses a go.mod the toolchain cannot parse" 1 "$work/checkunparseable" "--check v3.7.2"

# Running it twice must be a no-op, since the release procedure may re-run it.
check "is idempotent" 0 "$work/good" v3.7.0

echo
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
