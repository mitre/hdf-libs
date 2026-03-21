package twistlock

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwistlockFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp, "twistlock-to-hdf should be registered via init()")
		assert.Equal(t, "Twistlock", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects results with complianceDistribution at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"results": []any{
				map[string]any{
					"complianceDistribution": map[string]any{
						"critical": float64(0),
					},
				},
			},
		}
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects results with vulnerabilityDistribution at confidence 0.9", func(t *testing.T) {
		input := map[string]any{
			"results": []any{
				map[string]any{
					"vulnerabilityDistribution": map[string]any{
						"critical": float64(0),
					},
				},
			},
		}
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.9, fp.Fingerprint(input))
	})

	t.Run("detects single object with complianceDistribution at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"complianceDistribution": map[string]any{
				"critical": float64(0),
			},
		}
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("twistlock-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
