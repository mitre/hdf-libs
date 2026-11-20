#!/usr/bin/env bash
#
# Publishes a validated batch of snapshot archives to npm, one package per line
# of the packages file in that order. A version the registry already holds is
# skipped, a failed publish does not stop the later packages, and the final
# summary line counts published, already published and failed.
#
# Usage: publish-snapshot-packages.sh <version> <packages-file> <archives-dir>
#
# Exits 2 before any publication on a usage error, 1 when any package failed.

set -euo pipefail

usage() {
  echo "usage: ${0##*/} <version> <packages-file> <archives-dir>" >&2
  exit 2
}

[ $# -eq 3 ] || usage
readonly VERSION="$1"
packages_file="$2"
archives="$3"
readonly REGISTRY=https://registry.npmjs.org

[ -s "$packages_file" ] || { echo "ERROR: $packages_file missing or empty" >&2; usage; }
[ -d "$archives" ] || { echo "ERROR: $archives is not a directory" >&2; usage; }
# npm reads a bare dir/file.tgz spec as a GitHub owner/repo shorthand; / defeats that.
archives="$(cd "$archives" && pwd)"

packages=()
while read -r pkg; do
  [ -n "$pkg" ] || continue
  packages+=("$pkg")
done < "$packages_file"
[ "${#packages[@]}" -gt 0 ] ||
  { echo "ERROR: $packages_file lists no package" >&2; usage; }

for pkg in "${packages[@]}"; do
  archive="$archives/mitre-$pkg-$VERSION.tgz"
  [ -f "$archive" ] || { echo "ERROR: $archive is missing" >&2; usage; }
done

published=0
skipped=0
failed=0
failures=()
for pkg in "${packages[@]}"; do
  name="@mitre/$pkg"
  code="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 30 \
    "$REGISTRY/@mitre%2f$pkg/$VERSION")" || true
  case "${code:-000}" in
    200)
      # A published version is immutable, so a re-run resumes where the last one stopped.
      echo "already published: $name@$VERSION"
      skipped=$((skipped + 1))
      ;;
    404)
      if npm publish "$archives/mitre-$pkg-$VERSION.tgz" --access public --provenance \
        --ignore-scripts --tag snapshot-staging \
        "--registry=$REGISTRY" "--@mitre:registry=$REGISTRY"; then
        published=$((published + 1))
      else
        echo "npm publish failed for $name@$VERSION" >&2
        failed=$((failed + 1))
        failures+=("$name@$VERSION")
      fi
      ;;
    *)
      echo "could not read the registry for $name@$VERSION (HTTP ${code:-000})" >&2
      failed=$((failed + 1))
      failures+=("$name@$VERSION")
      ;;
  esac
done

echo "published: $published, already published: $skipped, failed: $failed"
if [ "$failed" -gt 0 ]; then
  echo "failed: ${failures[*]}" >&2
  exit 1
fi
