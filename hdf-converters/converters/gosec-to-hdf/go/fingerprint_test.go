package gosec

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGosecFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp, "gosec-to-hdf should be registered via init()")
		assert.Equal(t, "GoSec", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects GosecVersion with Issues at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"GosecVersion": "2.18.2",
			"Issues":       []any{},
			"Stats":        map[string]any{"files": float64(1)},
		}
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects Issues with Stats but no version at confidence 0.6", func(t *testing.T) {
		input := map[string]any{
			"Issues": []any{},
			"Stats":  map[string]any{"files": float64(1)},
		}
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.6, fp.Fingerprint(input))
	})

	t.Run("does not match Issues alone without Stats or version", func(t *testing.T) {
		input := map[string]any{
			"Issues": []any{},
		}
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("gosec-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
