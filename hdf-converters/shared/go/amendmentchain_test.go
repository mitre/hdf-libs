package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chainWaiver(id, reason string) hdf.StandaloneOverride {
	return hdf.StandaloneOverride{
		Type:          hdf.OverrideType("waiver"),
		RequirementID: id,
		Reason:        reason,
		AppliedBy:     hdf.Identity{Type: hdf.Email, Identifier: "admin@example.com"},
		AppliedAt:     time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2099, 12, 31, 0, 0, 0, 0, time.UTC),
	}
}

func TestChainOverrides(t *testing.T) {
	t.Run("leaves the first unlinked and chains the rest", func(t *testing.T) {
		overrides := []hdf.StandaloneOverride{
			chainWaiver("AC-1", "first"), chainWaiver("AC-2", "second"), chainWaiver("AC-3", "third"),
		}
		require.NoError(t, ChainOverrides(overrides))

		assert.Nil(t, overrides[0].PreviousChecksum)
		require.NotNil(t, overrides[1].PreviousChecksum)
		assert.Equal(t, hdf.Sha256, overrides[1].PreviousChecksum.Algorithm)
		assert.Len(t, overrides[1].PreviousChecksum.Value, 64)
		require.NotNil(t, overrides[2].PreviousChecksum)
		assert.NotEqual(t, overrides[1].PreviousChecksum.Value, overrides[2].PreviousChecksum.Value)
	})

	t.Run("is deterministic", func(t *testing.T) {
		a := []hdf.StandaloneOverride{chainWaiver("AC-1", "x"), chainWaiver("AC-2", "y")}
		b := []hdf.StandaloneOverride{chainWaiver("AC-1", "x"), chainWaiver("AC-2", "y")}
		require.NoError(t, ChainOverrides(a))
		require.NoError(t, ChainOverrides(b))
		assert.Equal(t, a[1].PreviousChecksum.Value, b[1].PreviousChecksum.Value)
	})

	t.Run("the link changes when the preceding override changes", func(t *testing.T) {
		before := []hdf.StandaloneOverride{chainWaiver("AC-1", "original"), chainWaiver("AC-2", "second")}
		after := []hdf.StandaloneOverride{chainWaiver("AC-1", "edited"), chainWaiver("AC-2", "second")}
		require.NoError(t, ChainOverrides(before))
		require.NoError(t, ChainOverrides(after))
		assert.NotEqual(t, before[1].PreviousChecksum.Value, after[1].PreviousChecksum.Value)
	})

	t.Run("re-chaining an already-chained set is stable", func(t *testing.T) {
		overrides := []hdf.StandaloneOverride{chainWaiver("AC-1", "first"), chainWaiver("AC-2", "second")}
		require.NoError(t, ChainOverrides(overrides))
		first := overrides[1].PreviousChecksum.Value
		require.NoError(t, ChainOverrides(overrides))
		assert.Equal(t, first, overrides[1].PreviousChecksum.Value)
	})

	t.Run("an empty set is a no-op", func(t *testing.T) {
		assert.NoError(t, ChainOverrides(nil))
	})

	// The TypeScript chainer asserts against this same fixture, so the two
	// languages are pinned to one chain rather than to each other's promises.
	t.Run("reproduces the checksums in the expected fixture", func(t *testing.T) {
		path := filepath.Join("..", "..", "converters", "openvex-to-hdf", "fixtures",
			"expected", "multi-status.openvex.json.hdf.json")
		raw, err := os.ReadFile(path) //nolint:gosec // fixture path is repo-relative
		require.NoError(t, err)

		var doc hdf.HDFAmendments
		require.NoError(t, json.Unmarshal(raw, &doc))
		require.GreaterOrEqual(t, len(doc.Overrides), 2)

		recorded := make([]*hdf.Checksum, len(doc.Overrides))
		for i := range doc.Overrides {
			recorded[i] = doc.Overrides[i].PreviousChecksum
		}

		require.NoError(t, ChainOverrides(doc.Overrides))
		for i := range doc.Overrides {
			if recorded[i] == nil {
				assert.Nilf(t, doc.Overrides[i].PreviousChecksum, "override %d", i)
				continue
			}
			require.NotNilf(t, doc.Overrides[i].PreviousChecksum, "override %d", i)
			assert.Equalf(t, recorded[i].Value, doc.Overrides[i].PreviousChecksum.Value, "override %d", i)
		}
	})
}
