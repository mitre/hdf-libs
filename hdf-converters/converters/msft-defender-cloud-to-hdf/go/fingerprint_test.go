package msftdefendercloud

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMsftDefenderCloudFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp, "msft-defender-cloud-to-hdf should be registered via init()")
		assert.Equal(t, "Microsoft Defender for Cloud", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects value array with properties.displayName at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"value": []any{
				map[string]any{
					"properties": map[string]any{
						"displayName": "Enable MFA",
					},
				},
			},
		}
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects empty value array at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"value": []any{},
		}
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-cloud-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
