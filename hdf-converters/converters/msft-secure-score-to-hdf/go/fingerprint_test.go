package msftsecurescore

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMsftSecureScoreFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp, "msft-secure-score-to-hdf should be registered via init()")
		assert.Equal(t, "Microsoft Secure Score", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects full shape with controlScores at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"secureScore": map[string]any{
				"value": []any{
					map[string]any{
						"controlScores": []any{
							map[string]any{"controlName": "MFAEnabled"},
						},
					},
				},
			},
			"profiles": map[string]any{
				"value": []any{},
			},
		}
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects shape without controlScores at confidence 0.8", func(t *testing.T) {
		input := map[string]any{
			"secureScore": map[string]any{
				"value": []any{},
			},
			"profiles": map[string]any{
				"value": []any{},
			},
		}
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.8, fp.Fingerprint(input))
	})

	t.Run("does not match without profiles", func(t *testing.T) {
		input := map[string]any{
			"secureScore": map[string]any{
				"value": []any{},
			},
		}
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("msft-secure-score-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
