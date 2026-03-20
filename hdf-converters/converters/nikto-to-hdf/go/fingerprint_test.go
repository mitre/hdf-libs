package nikto_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNiktoFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp, "nikto-to-hdf should be registered via init()")
		assert.Equal(t, "Nikto", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects vulnerabilities with host at confidence 0.95", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
			"host":            "example.com",
			"port":            "443",
		}
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.95, fp.Fingerprint(input))
	})

	t.Run("detects vulnerabilities without host/port at confidence 0.85", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
		}
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.85, fp.Fingerprint(input))
	})

	t.Run("does not match when host/port are not strings", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
			"host":            float64(123),
			"port":            float64(443),
		}
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.85, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("nikto-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
