package scoutsuite

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScoutsuiteFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp, "scoutsuite-to-hdf should be registered via init()")
		assert.Equal(t, "ScoutSuite", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects services object with last_run at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"services": map[string]any{
				"ec2": map[string]any{},
			},
			"last_run": map[string]any{
				"time": "2024-01-01",
			},
		}
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("does not match services without last_run", func(t *testing.T) {
		input := map[string]any{
			"services": map[string]any{},
		}
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match services as array", func(t *testing.T) {
		input := map[string]any{
			"services": []any{"ec2"},
			"last_run": map[string]any{},
		}
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("scoutsuite-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
