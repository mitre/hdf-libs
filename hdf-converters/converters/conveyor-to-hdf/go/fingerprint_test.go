package conveyor

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConveyorFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp, "conveyor-to-hdf should be registered via init()")
		assert.Equal(t, "Conveyor", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects api_response with results at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"api_response": map[string]any{
				"results": map[string]any{},
			},
		}
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects api_response without results at confidence 0.6", func(t *testing.T) {
		input := map[string]any{
			"api_response": map[string]any{},
		}
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.6, fp.Fingerprint(input))
	})

	t.Run("detects api_server_version at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"api_server_version": "1.2.3",
		}
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("conveyor-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
