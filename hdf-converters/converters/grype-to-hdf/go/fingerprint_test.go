package grype_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGrypeFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp, "grype-to-hdf should be registered via init()")
		assert.Equal(t, "Grype", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects matches with source at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"matches": []any{},
			"source":  map[string]any{"type": "image"},
		}
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects descriptor.name grype without matches at confidence 0.8", func(t *testing.T) {
		input := map[string]any{
			"descriptor": map[string]any{
				"name": "grype",
			},
		}
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("detects matches with descriptor.name grype at confidence 0.8", func(t *testing.T) {
		input := map[string]any{
			"matches": []any{},
			"descriptor": map[string]any{
				"name": "grype",
			},
		}
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("detects bare matches array at confidence 0.4", func(t *testing.T) {
		input := map[string]any{
			"matches": []any{},
		}
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.4, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("grype-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
