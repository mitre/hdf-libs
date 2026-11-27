#!/usr/bin/env bash
#
# Hermetic tests for .github/scripts/ensure-go-tool.sh using a fake go binary
# on PATH (no network access or real binary execution).

set -uo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TARGET="$script_dir/ensure-go-tool.sh"

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

mkdir -p "$work/bin"
cat > "$work/bin/go" <<'GOSTUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_GO_LOG"

emit_meta() {
  local mod="$1" pkg="$2" ver="$3" goos="$4" goarch="$5" dest="$6"
  cat > "$dest" <<EOF
$dest: go1.27.4
	path	$pkg
	mod	$mod	$ver	h1:fakehash=
	build	-buildmode=exe
	build	CGO_ENABLED=0
	build	GOOS=$goos
	build	GOARCH=$goarch
EOF
}

case "${1:-}" in
  env)
    case "${2:-}" in
      GOBIN) printf '%s\n' "${FAKE_GOBIN:-}" ;;
      GOPATH) printf '%s\n' "${FAKE_GOPATH:-}" ;;
      GOEXE) printf '%s\n' "${FAKE_GOEXE:-}" ;;
      GOOS) printf '%s\n' "${FAKE_GOOS:-linux}" ;;
      GOARCH) printf '%s\n' "${FAKE_GOARCH:-amd64}" ;;
      *) exit 1 ;;
    esac
    ;;
  version)
    [ "${2:-}" = "-m" ] || exit 1
    bin="${3:?}"
    [ -f "$bin" ] || { echo "could not open $bin" >&2; exit 1; }
    if grep -q '^CORRUPT$' "$bin" 2>/dev/null; then
      echo "could not read Go buildinfo from $bin" >&2
      exit 1
    fi
    cat "$bin"
    ;;
  install)
    [ "${FAKE_INSTALL_FAIL:-0}" -eq 0 ] || { echo "go: network disabled" >&2; exit 1; }
    spec="${2:?}"
    pkg="${spec%@*}"
    ver="${spec##*@}"
    dest_dir="${FAKE_GOBIN:-${FAKE_GOPATH:?}/bin}"
    mkdir -p "$dest_dir"
    name="${pkg##*/}${FAKE_GOEXE:-}"
    mod="${FAKE_INSTALL_MOD:-$pkg}"
    if [ "${FAKE_INSTALL_BAD_META:-0}" -eq 1 ]; then
      emit_meta "$mod" "$pkg" "v0.0.1-wrong" "${FAKE_GOOS:-linux}" "${FAKE_GOARCH:-amd64}" "$dest_dir/$name"
    else
      emit_meta "$mod" "$pkg" "$ver" "${FAKE_GOOS:-linux}" "${FAKE_GOARCH:-amd64}" "$dest_dir/$name"
    fi
    chmod +x "$dest_dir/$name"
    ;;
  *)
    echo "unexpected fake go subcommand: $*" >&2
    exit 1
    ;;
esac
GOSTUB
chmod +x "$work/bin/go"

write_cached_meta() {
  local mod="$1" pkg="$2" ver="$3" goos="$4" goarch="$5" dest="$6"
  mkdir -p "$(dirname "$dest")"
  cat > "$dest" <<EOF
$dest: go1.27.4
	path	$pkg
	mod	$mod	$ver	h1:cached=
	build	-buildmode=exe
	build	GOOS=$goos
	build	GOARCH=$goarch
EOF
  chmod +x "$dest"
}

begin() {
  case_dir="$work/$1"
  gopath="$case_dir/gopath"
  log="$case_dir/go.log"
  out="$case_dir/stdout"
  err="$case_dir/stderr"
  mkdir -p "$case_dir"
  : > "$log"
}

run_target() {
  local pkg="${1:-}" ver="${2:-}" name="${3:-}"
  local args=()
  [ -z "$pkg" ] || args+=("$pkg")
  [ -z "$ver" ] || args+=("$ver")
  [ -z "$name" ] || args+=("$name")
  PATH="$work/bin:$PATH" FAKE_GO_LOG="$log" FAKE_GOPATH="$gopath" \
    bash "$TARGET" "${args[@]}" > "$out" 2> "$err"
  rc=$?
}

readonly PKG="gotest.tools/gotestsum"
readonly VER="v1.13.0"
readonly OSV_MOD="github.com/google/osv-scanner/v2"
readonly OSV_PKG="github.com/google/osv-scanner/v2/cmd/osv-scanner"
readonly OSV_VER="v2.5.1"

# --- 1. valid cached binary is reused without go install ---
begin cache-hit
write_cached_meta "$PKG" "$PKG" "$VER" linux amd64 "$gopath/bin/gotestsum"
run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ]; then report "cache hit: exits 0" 0; else report "cache hit: exits 0" 1 "rc=$rc err=$(cat "$err")"; fi
if [ "$(cat "$out")" = "$gopath/bin/gotestsum" ]; then report "cache hit: prints resolved path on stdout" 0; else report "cache hit: prints resolved path on stdout" 1 "out=$(cat "$out")"; fi
if ! grep -q '^install ' "$log"; then report "cache hit: skips go install" 0; else report "cache hit: skips go install" 1 "$(cat "$log")"; fi

# --- 2. subpackage tool matches containing module prefix ---
begin subpkg-hit
write_cached_meta "$OSV_MOD" "$OSV_PKG" "$OSV_VER" linux amd64 "$gopath/bin/osv-scanner"
FAKE_INSTALL_MOD="$OSV_MOD" run_target "$OSV_PKG" "$OSV_VER"
if [ "$rc" -eq 0 ] && ! grep -q '^install ' "$log"; then report "subpackage cache hit: reuses tool when module is path prefix" 0; else report "subpackage cache hit: reuses tool when module is path prefix" 1 "$(cat "$log") $(cat "$err")"; fi

# --- 3. cache miss runs go install and returns new binary path ---
begin cache-miss
run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ] && [ "$(cat "$out")" = "$gopath/bin/gotestsum" ]; then report "cache miss: exits 0 and prints binary path" 0; else report "cache miss: exits 0 and prints binary path" 1 "rc=$rc err=$(cat "$err")"; fi
if grep -qFx "install $PKG@$VER" "$log"; then report "cache miss: invokes go install with version" 0; else report "cache miss: invokes go install with version" 1 "$(cat "$log")"; fi

# --- 4. wrong version in cached binary triggers reinstall ---
begin wrong-version
write_cached_meta "$PKG" "$PKG" "v1.12.0" linux amd64 "$gopath/bin/gotestsum"
run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ] && grep -qFx "install $PKG@$VER" "$log"; then report "wrong version: rejects stale cache and reinstalls" 0; else report "wrong version: rejects stale cache and reinstalls" 1 "$(cat "$log") $(cat "$err")"; fi

# --- 5. wrong GOARCH in cached binary triggers reinstall without executing it ---
begin wrong-arch
write_cached_meta "$PKG" "$PKG" "$VER" darwin amd64 "$gopath/bin/gotestsum"
FAKE_GOOS=darwin FAKE_GOARCH=arm64 run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ] && grep -qFx "install $PKG@$VER" "$log"; then report "wrong arch: rejects amd64 cache on arm64 host and reinstalls" 0; else report "wrong arch: rejects amd64 cache on arm64 host and reinstalls" 1 "$(cat "$log") $(cat "$err")"; fi

# --- 6. wrong main package path in cached binary triggers reinstall ---
begin wrong-pkg
write_cached_meta "$OSV_MOD" "$OSV_MOD/cmd/other" "$OSV_VER" linux amd64 "$gopath/bin/osv-scanner"
FAKE_INSTALL_MOD="$OSV_MOD" run_target "$OSV_PKG" "$OSV_VER"
if [ "$rc" -eq 0 ] && grep -qFx "install $OSV_PKG@$OSV_VER" "$log"; then report "wrong package path: rejects mismatched command from same module" 0; else report "wrong package path: rejects mismatched command from same module" 1 "$(cat "$log")"; fi

# --- 7. corrupted cached binary triggers reinstall ---
begin corrupt
mkdir -p "$gopath/bin"
printf 'CORRUPT\n' > "$gopath/bin/gotestsum"
chmod +x "$gopath/bin/gotestsum"
run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ] && grep -qFx "install $PKG@$VER" "$log"; then report "corrupt cache: rejects unreadable binary and reinstalls" 0; else report "corrupt cache: rejects unreadable binary and reinstalls" 1 "$(cat "$log")"; fi

# --- 8. go install failure exits nonzero ---
begin install-fail
FAKE_INSTALL_FAIL=1 run_target "$PKG" "$VER"
if [ "$rc" -ne 0 ]; then report "install failure: exits nonzero" 0; else report "install failure: exits nonzero" 1 "rc=$rc"; fi

# --- 9. post-install metadata mismatch fails closed ---
begin bad-post-meta
FAKE_INSTALL_BAD_META=1 run_target "$PKG" "$VER"
if [ "$rc" -ne 0 ]; then report "post-install mismatch: exits nonzero" 0; else report "post-install mismatch: exits nonzero" 1 "rc=$rc err=$(cat "$err")"; fi

# --- 10. GOBIN and Windows GOEXE=.exe override GOPATH/bin ---
begin gobin-windows
custom_bin="$case_dir/custom-gobin"
write_cached_meta "$PKG" "$PKG" "$VER" windows amd64 "$custom_bin/gotestsum.exe"
FAKE_GOBIN="$custom_bin" FAKE_GOEXE=".exe" FAKE_GOOS=windows FAKE_GOARCH=amd64 run_target "$PKG" "$VER"
if [ "$rc" -eq 0 ] && [ "$(cat "$out")" = "$custom_bin/gotestsum.exe" ] && ! grep -q '^install ' "$log"; then report "GOBIN + GOEXE=.exe: resolves and reuses windows binary path" 0; else report "GOBIN + GOEXE=.exe: resolves and reuses windows binary path" 1 "rc=$rc out=$(cat "$out") err=$(cat "$err")"; fi

# --- 11. missing required arguments returns usage error (exit 2) ---
begin usage
PATH="$work/bin:$PATH" FAKE_GO_LOG="$log" FAKE_GOPATH="$gopath" bash "$TARGET" > "$out" 2> "$err"
rc=$?
if [ "$rc" -eq 2 ]; then report "usage error: exits 2 on missing arguments" 0; else report "usage error: exits 2 on missing arguments" 1 "rc=$rc err=$(cat "$err")"; fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
