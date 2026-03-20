package hdftocsv

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHdfToCsvFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp, "hdf-to-csv should be registered via init()")
		assert.Equal(t, "HDF to CSV", fp.Label)
		assert.Equal(t, registry.DirectionExport, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputRaw, fp.OutputType)
	})

	t.Run("detects HDF v2 JSON with baselines at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"baselines": []any{
				map[string]any{"name": "profile1"},
			},
		}
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match when baselines is not an array", func(t *testing.T) {
		input := map[string]any{
			"baselines": "not-an-array",
		}
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match JSON without baselines", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("hdf-to-csv")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
