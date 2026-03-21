package trufflehog

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrufflehogFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp, "trufflehog-to-hdf should be registered via init()")
		assert.Equal(t, "TruffleHog", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects single finding with DetectorName and SourceMetadata at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"DetectorName":   "AWS",
			"SourceMetadata": map[string]any{"file": "secrets.txt"},
		}
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects array of findings at confidence 1.0", func(t *testing.T) {
		input := []any{
			map[string]any{
				"DetectorName":   "AWS",
				"SourceMetadata": map[string]any{"file": "secrets.txt"},
			},
		}
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects Raw and Verified at confidence 0.7", func(t *testing.T) {
		input := map[string]any{
			"Raw":      "AKIAIOSFODNN7EXAMPLE",
			"Verified": true,
		}
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.7, fp.Fingerprint(input))
	})

	t.Run("does not match empty array", func(t *testing.T) {
		input := []any{}
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("trufflehog-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
