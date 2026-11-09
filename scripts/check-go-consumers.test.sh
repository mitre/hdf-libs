#!/usr/bin/env bash
#
# Pins check-go-consumers.sh without the network.
#
# The checker's only honest run is against proxy.golang.org, so these cases
# drive it with a fake `go` on PATH that records every invocation and its
# environment and answers `go list` from fixtures. The one case that needs the
# real toolchain points GOPROXY at an empty file:// proxy. Fixtures are
# throwaway trees in a temp dir; the repo is never touched.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CHECKER="$script_dir/check-go-consumers.sh"
readonly VERSION="3.8.0-next.1.1"
readonly PREFIX="github.com/mitre/hdf-libs"

work="$(mktemp -d)"
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT

pass=0
fail=0

# --- fixtures ---------------------------------------------------------------

# A checkout with two library modules and one that ships a binary, plus the
# inventory the snapshot's tag job reads: one go.mod path per line.
make_checkout() {
  local root="$work/$1"
  mkdir -p "$root/scripts" "$root/liba" "$root/libb/go" "$root/tool"
  cp "$CHECKER" "$root/scripts/"
  printf 'module %s/liba/v3\n\ngo 1.26\n' "$PREFIX" > "$root/liba/go.mod"
  printf 'module %s/libb/go/v3\n\ngo 1.26\n' "$PREFIX" > "$root/libb/go/go.mod"
  printf 'module %s/tool/v3\n\ngo 1.26\n' "$PREFIX" > "$root/tool/go.mod"
  printf 'liba/go.mod\nlibb/go/go.mod\ntool/go.mod\n' > "$root/gomods.txt"
  printf '%s' "$root"
}

# The packages `go list` reports for the fixture modules: import path and name.
cat > "$work/packages.txt" <<EOF
$PREFIX/liba/v3 liba
$PREFIX/libb/go/v3 libb
$PREFIX/libb/go/v3/internal/x x
$PREFIX/tool/v3/cmd/tool main
$PREFIX/tool/v3/cmd/tool/cmd cmd
EOF

cat > "$work/consistent.txt" <<EOF
example.com/hdf-consumer
$PREFIX/liba/v3 v$VERSION
$PREFIX/libb/go/v3 v$VERSION
$PREFIX/tool/v3 v$VERSION
github.com/spf13/cobra v1.10.2
EOF

cat > "$work/older-sibling.txt" <<EOF
example.com/hdf-consumer
$PREFIX/liba/v3 v$VERSION
$PREFIX/libb/go/v3 v3.7.0
$PREFIX/tool/v3 v$VERSION
github.com/spf13/cobra v1.10.2
EOF

# The 7pki shape: a module the inventory never tagged, pulled in at the zero
# pseudo-version a replace used to paper over.
cat > "$work/untagged-sibling.txt" <<EOF
example.com/hdf-consumer
$PREFIX/liba/v3 v$VERSION
$PREFIX/libb/go/v3 v$VERSION
$PREFIX/testhdf/go/v3 v0.0.0-00010101000000-000000000000
$PREFIX/tool/v3 v$VERSION
EOF

cat > "$work/missing-module.txt" <<EOF
example.com/hdf-consumer
$PREFIX/liba/v3 v$VERSION
$PREFIX/libb/go/v3 v$VERSION
EOF

mkdir -p "$work/bin"
cat > "$work/bin/go" <<'EOF'
#!/usr/bin/env bash
# Stands in for the toolchain: records each call with the environment it saw,
# answers `go list` from fixtures, and never touches the network.
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GO_LOG"
printf 'PWD=%s GOWORK=%s GOFLAGS=%s GOMODCACHE=%s\n' \
  "$PWD" "${GOWORK-unset}" "${GOFLAGS-unset}" "${GOMODCACHE-unset}" >> "$FAKE_GO_ENV"
case "$1 ${2:-}" in
  "env GOPROXY") echo "https://proxy.golang.org,direct" ;;
  "mod init") printf 'module %s\n\ngo 1.26\n' "$3" > go.mod ;;
  "get "*)
    if [ "${FAKE_GO_INJECT_REPLACE:-0}" = 1 ]; then
      printf 'replace %s => ../sibling\n' "${2%@*}" >> go.mod
    fi ;;
  "list -m") cat "$FAKE_GO_LIST" ;;
  "list -f") awk -v m="${4%/...}" '$1 == m || index($1, m "/") == 1' "$FAKE_GO_PKGS" ;;
  "build "*) : ;;
  *) echo "fake go: unexpected invocation: $*" >&2; exit 97 ;;
esac
EOF
chmod +x "$work/bin/go"

# --- harness ----------------------------------------------------------------

got=0
# Runs the checker from a fixture checkout with the fake toolchain answering
# `go list -m all` from $1; extra arguments are environment overrides.
run_fake() {
  local root="$1" list="$2"
  shift 2
  : > "$work/go.log"
  : > "$work/go.env"
  got=0
  ( cd "$root" && env PATH="$work/bin:$PATH" FAKE_GO_LOG="$work/go.log" FAKE_GO_ENV="$work/go.env" \
      FAKE_GO_LIST="$list" FAKE_GO_PKGS="$work/packages.txt" "$@" \
      ./scripts/check-go-consumers.sh "$VERSION" gomods.txt ) > "$work/out.log" 2>&1 || got=$?
}

ok() {
  echo "ok   $1"
  pass=$((pass + 1))
}

bad() {
  echo "FAIL $1"
  sed 's/^/       /' "$work/out.log"
  fail=$((fail + 1))
}

expect_exit() {
  local label="$1" want="$2"
  if [ "$got" -eq "$want" ]; then ok "$label"; else bad "$label — expected exit $want, got $got"; fi
}

expect_output() {
  local label="$1" needle="$2"
  if grep -qF -- "$needle" "$work/out.log"; then ok "$label"; else bad "$label — output lacks '$needle'"; fi
}

# One output line must carry every needle: a dump of the build list that happens
# to contain them is not a failure that names them.
expect_line() {
  local label="$1"
  shift
  local pattern="FAIL"
  for needle in "$@"; do pattern="$pattern.*$needle"; done
  if grep -qE -- "$pattern" "$work/out.log"; then ok "$label"; else bad "$label — no line matching '$pattern'"; fi
}

expect_no_output() {
  local label="$1" needle="$2"
  if grep -qF -- "$needle" "$work/out.log"; then bad "$label — output contains '$needle'"; else ok "$label"; fi
}

expect_log() {
  local label="$1" pattern="$2"
  if grep -qE -- "$pattern" "$work/go.log"; then ok "$label"; else bad "$label — no go call matching '$pattern'"; fi
}

expect_no_log() {
  local label="$1" pattern="$2"
  if grep -qE -- "$pattern" "$work/go.log"; then bad "$label — a go call matched '$pattern'"; else ok "$label"; fi
}

# --- a consistent graph passes, so a later failure means something real -----
root="$(make_checkout consistent)"
run_fake "$root" "$work/consistent.txt"
expect_exit "a consistent build list passes" 0
expect_output "the pass reports how many hdf-libs modules it checked" "(3 modules)"

# --- the inventory expands to the published module path of each go.mod ------
want="$(printf 'get %s/liba/v3@v%s\nget %s/libb/go/v3@v%s\nget %s/tool/v3@v%s\n' \
  "$PREFIX" "$VERSION" "$PREFIX" "$VERSION" "$PREFIX" "$VERSION")"
have="$(grep '^get ' "$work/go.log" || true)"
if [ "$have" = "$want" ]; then
  ok "each inventory go.mod is fetched by its module directive at the snapshot version"
else
  bad "each inventory go.mod is fetched by its module directive at the snapshot version — got: $have"
fi

# --- the consumer lives outside the checkout with the environment the AC names
host_modcache="$(go env GOMODCACHE)"
if [ "$(grep -vc 'GOWORK=off GOFLAGS=-mod=mod ' "$work/go.env" || true)" -eq 0 ] &&
   [ "$(grep -c . "$work/go.env")" -gt 0 ]; then
  ok "every go call runs with GOWORK=off and GOFLAGS=-mod=mod"
else
  bad "every go call runs with GOWORK=off and GOFLAGS=-mod=mod — env log: $(cat "$work/go.env")"
fi
if [ "$(grep -c "PWD=$root" "$work/go.env" || true)" -eq 0 ] &&
   [ "$(grep -c "GOMODCACHE=$host_modcache" "$work/go.env" || true)" -eq 0 ] &&
   [ "$(grep -c "GOMODCACHE=$root" "$work/go.env" || true)" -eq 0 ]; then
  ok "the consumer and its module cache live outside the checkout and the host cache"
else
  bad "the consumer and its module cache live outside the checkout and the host cache — env log: $(cat "$work/go.env")"
fi
if [ "$(sed -n 's/.*GOMODCACHE=//p' "$work/go.env" | sort -u | grep -c .)" -eq 1 ]; then
  ok "one module cache serves every go call"
else
  bad "one module cache serves every go call — env log: $(cat "$work/go.env")"
fi

# --- libraries are built with ./..., the binary module's main is linked ------
expect_log "each library module is built package by package" "^build $PREFIX/liba/v3/\.\.\.$"
expect_log "each library module is built package by package (nested go dir)" "^build $PREFIX/libb/go/v3/\.\.\.$"
expect_log "the binary module's main package is linked, as go install would" \
  "^build -o [^ ]+/ $PREFIX/tool/v3/cmd/tool$"
expect_no_log "no module's tests are run" "^test "
expect_no_log "no module's code is run" "^run "
expect_log "the build list is read after building" "^list -m all$"

# --- a sibling at an older version fails naming the module and both versions -
root="$(make_checkout older)"
run_fake "$root" "$work/older-sibling.txt"
expect_exit "a sibling resolved to an older version fails" 1
expect_line "the failure names the module, the resolved version and the snapshot version" \
  "$PREFIX/libb/go/v3" "v3\.7\.0" "v3\.8\.0-next\.1\.1"

# --- an untagged sibling outside the inventory fails the same way -----------
root="$(make_checkout untagged)"
run_fake "$root" "$work/untagged-sibling.txt"
expect_exit "an untagged sibling at the zero pseudo-version fails" 1
expect_line "the failure names the untagged module, its pseudo-version and the snapshot version" \
  "$PREFIX/testhdf/go/v3" "v0\.0\.0-00010101000000-000000000000" "v3\.8\.0-next\.1\.1"

# --- an inventory module absent from the build list is not a pass -----------
root="$(make_checkout absent)"
run_fake "$root" "$work/missing-module.txt"
expect_exit "an inventory module missing from the build list fails" 1
expect_line "the failure names the missing module" "$PREFIX/tool/v3"

# --- a replace directive stops the run before anything is built -------------
root="$(make_checkout replaced)"
run_fake "$root" "$work/consistent.txt" FAKE_GO_INJECT_REPLACE=1
expect_exit "a replace directive in the consumer fails" 1
expect_output "the failure names the replace" "replace"
expect_no_log "nothing is built once a replace is present" "^build "

# --- an inventory entry the checkout lacks is an error, not a skip ----------
root="$(make_checkout missing)"
printf 'liba/go.mod\ngone/go.mod\n' > "$root/gomods.txt"
run_fake "$root" "$work/consistent.txt"
expect_exit "an inventory entry with no go.mod errors" 1
expect_output "the error names the entry" "gone/go.mod"
expect_no_log "nothing is fetched when the inventory is wrong" "^get "

# --- a go.mod without a module directive is an error --------------------------
root="$(make_checkout nomodule)"
printf 'go 1.26\n' > "$root/liba/go.mod"
run_fake "$root" "$work/consistent.txt"
expect_exit "a go.mod with no module directive errors" 1
expect_output "the error names the go.mod" "liba/go.mod"

# --- a version that is not a module version is refused up front -------------
root="$(make_checkout badversion)"
got=0
( cd "$root" && env PATH="$work/bin:$PATH" FAKE_GO_LOG="$work/go.log" FAKE_GO_ENV="$work/go.env" \
    ./scripts/check-go-consumers.sh "latest" gomods.txt ) > "$work/out.log" 2>&1 || got=$?
expect_exit "a non-semver version is refused" 1

# --- a module the proxy does not serve fails with the path and Go's error ---
# Real toolchain, empty file:// proxy and no fallback: every fetch misses.
# GOSUMDB=off and GOTOOLCHAIN=local keep the run offline; the checker itself
# sets neither.
root="$(make_checkout unserved)"
mkdir -p "$work/emptyproxy"
got=0
( cd "$root" && env GOPROXY="file://$work/emptyproxy" GOSUMDB=off GOTOOLCHAIN=local \
    ./scripts/check-go-consumers.sh "$VERSION" gomods.txt ) > "$work/out.log" 2>&1 || got=$?
expect_exit "a module the proxy does not serve fails" 1
expect_output "the failure names the module and version asked for" "$PREFIX/liba/v3@v$VERSION"
expect_output "the failure carries Go's own error" "$work/emptyproxy"
expect_no_output "nothing is built when a module is unserved" "ok   build"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
