package msftdefenderendpoint

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMsftDefenderEndpointFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp, "msft-defender-endpoint-to-hdf should be registered via init()")
		assert.Equal(t, "Microsoft Defender for Endpoint", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects MDE alerts at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"value": []any{
				map[string]any{
					"severity": "High",
					"category": "Malware",
					"evidence": []any{
						map[string]any{"entityType": "File"},
					},
				},
			},
		}
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match value array without required fields", func(t *testing.T) {
		input := map[string]any{
			"value": []any{
				map[string]any{
					"severity": "High",
				},
			},
		}
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match empty value array", func(t *testing.T) {
		input := map[string]any{
			"value": []any{},
		}
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-endpoint-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
