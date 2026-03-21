package sarif

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSarifFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp, "sarif-to-hdf should be registered via init()")
		assert.Equal(t, "SARIF", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects SARIF JSON at confidence 0.9", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.9, fp.Fingerprint(input))
	})

	t.Run("does not match GoSec JSON", func(t *testing.T) {
		input := map[string]any{
			"GosecVersion": "2.18.2",
			"Issues":       []any{},
			"Stats":        map[string]any{"files": float64(1)},
		}
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match when version is number", func(t *testing.T) {
		input := map[string]any{
			"version": float64(2),
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match when runs is object", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    map[string]any{},
		}
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("sarif-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
