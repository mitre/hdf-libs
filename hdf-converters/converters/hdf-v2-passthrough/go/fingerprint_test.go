package hdfv2passthrough

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHdfV2PassthroughFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp, "hdf-v2-passthrough should be registered via init()")
		assert.Equal(t, "HDF v2", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects HDF v2 JSON with baselines array at confidence 0.8", func(t *testing.T) {
		input := map[string]any{
			"baselines": []any{
				map[string]any{"name": "profile1"},
			},
		}
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("detects HDF v2 with empty baselines array at confidence 0.8", func(t *testing.T) {
		input := map[string]any{
			"baselines": []any{},
		}
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("does not match when baselines is not an array", func(t *testing.T) {
		input := map[string]any{
			"baselines": "not-an-array",
		}
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match JSON without baselines", func(t *testing.T) {
		input := map[string]any{
			"version":  "2.1.0",
			"profiles": []any{},
		}
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-v2-passthrough")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
