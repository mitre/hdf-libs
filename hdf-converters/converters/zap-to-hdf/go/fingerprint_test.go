package zap_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZapFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp, "zap-to-hdf should be registered via init()")
		assert.Equal(t, "OWASP ZAP", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects site array with @version at confidence 0.95", func(t *testing.T) {
		input := map[string]any{
			"site":       []any{},
			"@version":   "2.14.0",
			"@generated": "2024-01-01",
		}
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.95, fp.Fingerprint(input))
	})

	t.Run("detects site array without version at confidence 0.85", func(t *testing.T) {
		input := map[string]any{
			"site": []any{},
		}
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.85, fp.Fingerprint(input))
	})

	t.Run("does not match when @version is not a string", func(t *testing.T) {
		input := map[string]any{
			"site":     []any{},
			"@version": float64(2),
		}
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.85, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("zap-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
