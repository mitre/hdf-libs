package legacyhdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLegacyHdfFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp, "legacyhdf-to-hdf should be registered via init()")
		assert.Equal(t, "HDF v1 (Legacy)", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects HDF v1 structure at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"version":  "1.0.0",
			"profiles": []any{map[string]any{"name": "profile1"}},
			"platform": map[string]any{"name": "ubuntu", "release": "20.04"},
		}
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match when baselines array is present (HDF v2)", func(t *testing.T) {
		input := map[string]any{
			"version":   "2.0.0",
			"profiles":  []any{},
			"platform":  map[string]any{"name": "ubuntu"},
			"baselines": []any{},
		}
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match when version is not a string", func(t *testing.T) {
		input := map[string]any{
			"version":  float64(1),
			"profiles": []any{},
			"platform": map[string]any{"name": "ubuntu"},
		}
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match when profiles is not an array", func(t *testing.T) {
		input := map[string]any{
			"version":  "1.0.0",
			"profiles": "not-an-array",
			"platform": map[string]any{"name": "ubuntu"},
		}
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match when platform is not an object", func(t *testing.T) {
		input := map[string]any{
			"version":  "1.0.0",
			"profiles": []any{},
			"platform": "not-an-object",
		}
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("legacyhdf-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
