package snyk

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnykFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp, "snyk-to-hdf should be registered via init()")
		assert.Equal(t, "Snyk", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects single project with packageManager at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
			"packageManager":  "npm",
		}
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects multi-project array at confidence 1.0", func(t *testing.T) {
		input := []any{
			map[string]any{
				"vulnerabilities": []any{},
				"packageManager":  "npm",
			},
		}
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects vulnerabilities without packageManager at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
		}
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match empty array", func(t *testing.T) {
		input := []any{}
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("snyk-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
