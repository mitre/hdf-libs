package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const oldCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
  "metadata": {
    "timestamp": "2025-01-01T00:00:00Z",
    "tools": [{"name": "test"}]
  },
  "components": [
    {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
    {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
    {"type": "library", "name": "old-lib", "version": "1.0.0", "purl": "pkg:npm/old-lib@1.0.0"}
  ]
}`

const newCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000002",
  "metadata": {
    "timestamp": "2025-01-02T00:00:00Z",
    "tools": [{"name": "test"}]
  },
  "components": [
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    {"type": "library", "name": "express", "version": "4.18.0", "purl": "pkg:npm/express@4.18.0"},
    {"type": "library", "name": "new-lib", "version": "2.0.0", "purl": "pkg:npm/new-lib@2.0.0"}
  ]
}`

const emptyCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "metadata": {"timestamp": "2025-01-01T00:00:00Z", "tools": [{"name": "test"}]},
  "components": []
}`

func TestDiffSBOMs_CycloneDX(t *testing.T) {
	result, err := DiffSBOMs([]byte(oldCycloneDX), []byte(newCycloneDX))
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify counts
	assert.Equal(t, 1, result.Added, "expected 1 added package")
	assert.Equal(t, 1, result.Removed, "expected 1 removed package")
	assert.Equal(t, 1, result.Updated, "expected 1 updated package")
	assert.Equal(t, 1, result.Unchanged, "expected 1 unchanged package")

	// Verify we have 4 diffs total
	require.Len(t, result.PackageDiffs, 4)

	// Build a lookup by name for easier assertions
	byName := make(map[string]PackageDiff)
	for _, d := range result.PackageDiffs {
		byName[d.Name] = d
	}

	// express: unchanged
	express, ok := byName["express"]
	require.True(t, ok, "expected express in diffs")
	assert.Equal(t, "unchanged", express.State)

	// lodash: updated
	lodash, ok := byName["lodash"]
	require.True(t, ok, "expected lodash in diffs")
	assert.Equal(t, "updated", lodash.State)
	assert.Equal(t, "4.17.20", lodash.OldVersion)
	assert.Equal(t, "4.17.21", lodash.NewVersion)

	// old-lib: removed
	oldLib, ok := byName["old-lib"]
	require.True(t, ok, "expected old-lib in diffs")
	assert.Equal(t, "removed", oldLib.State)
	assert.Equal(t, "1.0.0", oldLib.OldVersion)

	// new-lib: added
	newLib, ok := byName["new-lib"]
	require.True(t, ok, "expected new-lib in diffs")
	assert.Equal(t, "added", newLib.State)
	assert.Equal(t, "2.0.0", newLib.NewVersion)
}

func TestDiffSBOMs_DeterministicOrder(t *testing.T) {
	result, err := DiffSBOMs([]byte(oldCycloneDX), []byte(newCycloneDX))
	require.NoError(t, err)

	// Should be sorted by name
	for i := 1; i < len(result.PackageDiffs); i++ {
		assert.True(t, result.PackageDiffs[i-1].Name <= result.PackageDiffs[i].Name,
			"diffs should be sorted by name: %s should come before %s",
			result.PackageDiffs[i-1].Name, result.PackageDiffs[i].Name)
	}
}

func TestDiffSBOMs_IdenticalSBOMs(t *testing.T) {
	result, err := DiffSBOMs([]byte(oldCycloneDX), []byte(oldCycloneDX))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Removed)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 3, result.Unchanged)
}

func TestDiffSBOMs_EmptySBOMs(t *testing.T) {
	result, err := DiffSBOMs([]byte(emptyCycloneDX), []byte(emptyCycloneDX))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.PackageDiffs)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Removed)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 0, result.Unchanged)
}

func TestDiffSBOMs_InvalidInput(t *testing.T) {
	_, err := DiffSBOMs([]byte("not json"), []byte(newCycloneDX))
	assert.Error(t, err, "expected error for invalid old SBOM")
	assert.Contains(t, err.Error(), "failed to parse old SBOM")

	_, err = DiffSBOMs([]byte(oldCycloneDX), []byte("not json"))
	assert.Error(t, err, "expected error for invalid new SBOM")
	assert.Contains(t, err.Error(), "failed to parse new SBOM")
}

func TestDiffSBOMs_PurlInOutput(t *testing.T) {
	result, err := DiffSBOMs([]byte(oldCycloneDX), []byte(newCycloneDX))
	require.NoError(t, err)

	// At least some diffs should have non-empty PURL values
	hasPurl := false
	for _, d := range result.PackageDiffs {
		if d.Purl != "" {
			hasPurl = true
			break
		}
	}
	assert.True(t, hasPurl, "expected at least one diff with a non-empty PURL")
}

func TestDiffSBOMs_AllRemoved(t *testing.T) {
	result, err := DiffSBOMs([]byte(oldCycloneDX), []byte(emptyCycloneDX))
	require.NoError(t, err)
	assert.Equal(t, 3, result.Removed)
	assert.Equal(t, 0, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 0, result.Unchanged)
}

func TestDiffSBOMs_AllAdded(t *testing.T) {
	result, err := DiffSBOMs([]byte(emptyCycloneDX), []byte(newCycloneDX))
	require.NoError(t, err)
	assert.Equal(t, 0, result.Removed)
	assert.Equal(t, 3, result.Added)
	assert.Equal(t, 0, result.Updated)
	assert.Equal(t, 0, result.Unchanged)
}
