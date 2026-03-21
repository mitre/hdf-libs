package deptrack

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeptrackFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp, "deptrack-to-hdf should be registered via init()")
		assert.Equal(t, "Dependency-Track", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects full FPF shape at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"findings": []any{},
			"project":  map[string]any{"name": "test"},
			"meta":     map[string]any{"totalCount": float64(0)},
		}
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects findings with vulnerability.vulnId at confidence 0.9", func(t *testing.T) {
		input := map[string]any{
			"findings": []any{
				map[string]any{
					"vulnerability": map[string]any{
						"vulnId": "CVE-2021-12345",
					},
				},
			},
		}
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.9, fp.Fingerprint(input))
	})

	t.Run("detects bare findings array at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"findings": []any{},
		}
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("deptrack-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
