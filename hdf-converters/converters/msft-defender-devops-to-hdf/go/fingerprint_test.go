package msftdefenderdevops

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMsftDefenderDevopsFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp, "msft-defender-devops-to-hdf should be registered via init()")
		assert.Equal(t, "Microsoft Defender for DevOps", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects SARIF with MSDO tool driver at confidence 0.95", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs": []any{
				map[string]any{
					"tool": map[string]any{
						"driver": map[string]any{
							"name":         "Microsoft Security DevOps",
							"organization": "Microsoft",
						},
					},
				},
			},
		}
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.95, fp.Fingerprint(input))
	})

	t.Run("does not match plain SARIF without MSDO driver", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs": []any{
				map[string]any{
					"tool": map[string]any{
						"driver": map[string]any{
							"name": "eslint",
						},
					},
				},
			},
		}
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"Issues":       []any{},
			"GosecVersion": "2.18.2",
		}
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-defender-devops-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
