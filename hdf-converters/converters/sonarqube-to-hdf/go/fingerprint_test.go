package sonarqube

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSonarqubeFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp, "sonarqube-to-hdf should be registered via init()")
		assert.Equal(t, "SonarQube", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects issues with rule and component at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"issues": []any{
				map[string]any{
					"rule":      "java:S1135",
					"component": "src/Main.java",
				},
			},
		}
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects empty issues array at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"issues": []any{},
		}
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("sonarqube-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
