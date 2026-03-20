package neuvector

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNeuvectorFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp, "neuvector-to-hdf should be registered via init()")
		assert.Equal(t, "NeuVector", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects report.vulnerabilities with name and package_name at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"report": map[string]any{
				"vulnerabilities": []any{
					map[string]any{
						"name":         "CVE-2021-12345",
						"package_name": "openssl",
					},
				},
			},
		}
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects empty vulnerabilities at confidence 0.7", func(t *testing.T) {
		input := map[string]any{
			"report": map[string]any{
				"vulnerabilities": []any{},
			},
		}
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.7, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("neuvector-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
