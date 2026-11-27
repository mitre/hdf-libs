#!/usr/bin/env bash
#
# Hermetic tests for .github/scripts/test-go-junit.sh in an isolated temporary
# git repository using fake go, jq, and cached gotestsum binaries.

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET="$script_dir/test-go-junit.sh"

work="$(mktemp -d)" || { echo "cannot create temp dir" >&2; exit 1; }
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

setup_case() {
  local name="$1"
  case_dir="$work/$name"
  repo="$case_dir/repo"
  bin="$case_dir/bin"
  gopath="$case_dir/gopath"
  go_log="$case_dir/go.log"
  gotest_log="$case_dir/gotestsum.log"
  out="$case_dir/stdout"
  err="$case_dir/stderr"

  mkdir -p "$repo/mod-a" "$repo/mod-b" "$bin" "$gopath/bin"
  git -C "$repo" init -q
  : > "$go_log"
  : > "$gotest_log"

  cat > "$gopath/bin/gotestsum" <<'GOTESTSUM'
#!/usr/bin/env bash
set -euo pipefail
printf '%s:%s\n' "$PWD" "$*" >> "$FAKE_GOTESTSUM_LOG"
junit=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "--junitfile" ]; then
    junit="$arg"
  fi
  prev="$arg"
done
mod_name="$(basename "$PWD")"
if [ "${FAKE_EMPTY_JUNIT_MOD:-}" != "$mod_name" ]; then
  printf '<testsuites></testsuites>\n' > "$junit"
fi
if [ "${FAKE_FAIL_MOD:-}" = "$mod_name" ]; then
  exit 1
fi
GOTESTSUM
  chmod +x "$gopath/bin/gotestsum"

  # Embed buildinfo lines after an initial header comment so fake `go version -m`
  # identifies the cached gotestsum binary as valid for gotest.tools/gotestsum.
  cat > "$bin/go" <<'GOSTUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GO_LOG"
case "${1:-}" in
  env)
    case "${2:-}" in
      GOBIN) printf '\n' ;;
      GOPATH) printf '%s\n' "$FAKE_GOPATH" ;;
      GOEXE) printf '\n' ;;
      GOOS) printf 'linux\n' ;;
      GOARCH) printf 'amd64\n' ;;
      *) exit 1 ;;
    esac
    ;;
  version)
    [ "${2:-}" = "-m" ] || exit 1
    cat <<EOF
${3}: go1.27.4
	path	gotest.tools/gotestsum
	mod	gotest.tools/gotestsum	v1.13.0	h1:cached=
	build	GOOS=linux
	build	GOARCH=amd64
EOF
    ;;
  work)
    cat <<'JSON'
{"Use":[{"DiskPath":"./mod-a"},{"DiskPath":"./mod-b"}]}
JSON
    ;;
  tool)
    [ "${2:-}" = "cover" ] || exit 1
    echo "total: (statements) 88.0%"
    ;;
  install)
    echo "unexpected direct go install when cached binary is valid" >&2
    exit 1
    ;;
  *)
    echo "unexpected fake go command: $*" >&2
    exit 1
    ;;
esac
GOSTUB
  chmod +x "$bin/go"

  cat > "$bin/jq" <<'JQSTUB'
#!/usr/bin/env bash
printf './mod-a\n./mod-b\n'
JQSTUB
  chmod +x "$bin/jq"
}

run_case() {
  (
    cd "$repo" && \
      PATH="$bin:$PATH" \
      FAKE_GOPATH="$gopath" \
      FAKE_GO_LOG="$go_log" \
      FAKE_GOTESTSUM_LOG="$gotest_log" \
      OS_TAG="ubuntu-latest" \
      GOTESTSUM_VERSION="v1.13.0" \
      bash "$TARGET" > "$out" 2> "$err"
  )
  rc=$?
}

# --- 1. reuses cached gotestsum and writes per-module JUnit ---
setup_case happy
GO_COVERAGE="" run_case
if [ "$rc" -eq 0 ]; then report "happy path: exits 0" 0; else report "happy path: exits 0" 1 "rc=$rc err=$(cat "$err")"; fi
if ! grep -q '^install ' "$go_log"; then report "happy path: reuses valid cached gotestsum without go install" 0; else report "happy path: reuses valid cached gotestsum without go install" 1 "$(cat "$go_log")"; fi
if [ -s "$repo/test-artifacts/go-mod-a-ubuntu-latest.xml" ] && [ -s "$repo/test-artifacts/go-mod-b-ubuntu-latest.xml" ]; then report "happy path: writes non-empty JUnit files for all workspace modules" 0; else report "happy path: writes non-empty JUnit files for all workspace modules" 1 "$(ls -la "$repo/test-artifacts" 2>&1)"; fi

# --- 2. GO_COVERAGE=1 enables coverprofile and runs go tool cover ---
setup_case coverage
GO_COVERAGE=1 run_case
if [ "$rc" -eq 0 ] && grep -q -- '-coverprofile=coverage.out' "$gotest_log" && grep -q '^tool cover -func=coverage.out$' "$go_log"; then report "coverage mode: passes -coverprofile and inspects coverage" 0; else report "coverage mode: passes -coverprofile and inspects coverage" 1 "gotest=$(cat "$gotest_log") go=$(cat "$go_log") err=$(cat "$err")"; fi

# --- 3. failing module test fails closed ---
setup_case test-fail
FAKE_FAIL_MOD=mod-b run_case
if [ "$rc" -ne 0 ]; then report "module test failure: exits nonzero" 0; else report "module test failure: exits nonzero" 1 "rc=$rc"; fi

# --- 4. empty or missing JUnit file fails closed ---
setup_case missing-junit
FAKE_EMPTY_JUNIT_MOD=mod-a run_case
if [ "$rc" -ne 0 ] && grep -qF "::error::missing JUnit output for ./mod-a" "$out"; then report "missing JUnit output: emits error and exits nonzero" 0; else report "missing JUnit output: emits error and exits nonzero" 1 "rc=$rc out=$(cat "$out") err=$(cat "$err")"; fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
