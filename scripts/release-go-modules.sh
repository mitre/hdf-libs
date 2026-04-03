#!/usr/bin/env bash
# release-go-modules.sh — Tag Go modules for release.
#
# Go modules in a monorepo need individual tags (e.g. hdf-cli/v2.0.0).
# The replace directives in go.mod files are for local development only
# and must be stripped before tagging, otherwise consumers get build errors.
#
# Usage:
#   ./scripts/release-go-modules.sh v2.0.0
#   ./scripts/release-go-modules.sh v2.0.0 --dry-run
#
# This script:
#   1. Strips replace directives from all go.mod files
#   2. Runs go mod tidy in each module
#   3. Creates a commit with the stripped go.mod files
#   4. Tags each Go module with the version
#   5. Reverts the go.mod changes (restores replace directives for dev)
#
# After running, push the tags:
#   git push origin --tags

set -euo pipefail

VERSION="${1:-}"
DRY_RUN="${2:-}"

if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version> [--dry-run]"
  echo "Example: $0 v2.0.0"
  exit 1
fi

if [[ ! "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
  echo "Error: version must start with 'v' (e.g. v2.0.0)"
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Go modules that need release tags
# Format: "module-dir tag-prefix"
GO_MODULES=(
  "hdf-cli hdf-cli"
  "hdf-converters hdf-converters"
  "hdf-mappings/go hdf-mappings/go"
  "hdf-validators/go hdf-validators/go"
  "hdf-parsers/go hdf-parsers/go"
  "hdf-generators/go hdf-generators/go"
  "hdf-schema/dist/go hdf-schema/dist/go"
)

echo "=== Stripping replace directives ==="
for entry in "${GO_MODULES[@]}"; do
  dir="${entry%% *}"
  mod="$dir/go.mod"
  if [ -f "$mod" ] && grep -q "^replace" "$mod"; then
    echo "  Stripping: $mod"
    if [ "$DRY_RUN" != "--dry-run" ]; then
      sed -i.bak '/^replace /d' "$mod"
      rm -f "$mod.bak"
    fi
  fi
done

echo ""
echo "=== Running go mod tidy ==="
for entry in "${GO_MODULES[@]}"; do
  dir="${entry%% *}"
  if [ -f "$dir/go.mod" ]; then
    echo "  Tidying: $dir"
    if [ "$DRY_RUN" != "--dry-run" ]; then
      (cd "$dir" && go mod tidy 2>/dev/null || true)
    fi
  fi
done

echo ""
echo "=== Creating tags ==="
for entry in "${GO_MODULES[@]}"; do
  dir="${entry%% *}"
  prefix="${entry##* }"
  tag="$prefix/$VERSION"
  echo "  Tag: $tag"
  if [ "$DRY_RUN" != "--dry-run" ]; then
    git tag -a "$tag" -m "Release $tag"
  fi
done

# Also create the root version tag
echo "  Tag: $VERSION (root)"
if [ "$DRY_RUN" != "--dry-run" ]; then
  git tag -a "$VERSION" -m "Release $VERSION"
fi

echo ""
echo "=== Restoring replace directives ==="
if [ "$DRY_RUN" != "--dry-run" ]; then
  git checkout -- '*/go.mod' '*/go.sum' 2>/dev/null || true
fi

echo ""
if [ "$DRY_RUN" = "--dry-run" ]; then
  echo "Dry run complete. No changes made."
else
  echo "Tags created. Push with:"
  echo "  git push origin --tags"
fi
