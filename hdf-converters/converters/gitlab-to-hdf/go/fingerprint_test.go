package gitlab_to_hdf

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitlabFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp, "gitlab-to-hdf should be registered via init()")
		assert.Equal(t, "GitLab", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects vulnerabilities with scan.type at confidence 0.9", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
			"scan": map[string]any{
				"type": "sast",
			},
		}
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.9, fp.Fingerprint(input))
	})

	t.Run("detects vulnerabilities with scan but no type at confidence 0.7", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
			"scan":            map[string]any{},
		}
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.7, fp.Fingerprint(input))
	})

	t.Run("detects bare vulnerabilities array at confidence 0.5", func(t *testing.T) {
		input := map[string]any{
			"vulnerabilities": []any{},
		}
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.5, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("gitlab-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
