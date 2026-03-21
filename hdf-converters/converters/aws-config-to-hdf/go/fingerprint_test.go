package awsconfig

import (
	"testing"

	"github.com/mitre/hdf-converters/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAwsConfigFingerprint(t *testing.T) {
	t.Run("is registered with correct metadata", func(t *testing.T) {
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp, "aws-config-to-hdf should be registered via init()")
		assert.Equal(t, "AWS Config", fp.Label)
		assert.Equal(t, registry.DirectionIngest, fp.Direction)
		assert.Equal(t, registry.FamilyJSON, fp.InputFamily)
		assert.Equal(t, registry.OutputResults, fp.OutputType)
	})

	t.Run("detects ConfigRules array at confidence 1.0", func(t *testing.T) {
		input := map[string]any{
			"ConfigRules": []any{},
		}
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 1.0, fp.Fingerprint(input))
	})

	t.Run("detects individual ConfigRuleName at confidence 0.7", func(t *testing.T) {
		input := map[string]any{
			"ConfigRuleName": "s3-bucket-public-read-prohibited",
		}
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.7, fp.Fingerprint(input))
	})

	t.Run("does not match different format", func(t *testing.T) {
		input := map[string]any{
			"version": "2.1.0",
			"runs":    []any{},
		}
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(input))
	})

	t.Run("does not match nil input", func(t *testing.T) {
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint(nil))
	})

	t.Run("does not match string input", func(t *testing.T) {
		fp := registry.GetFingerprint("aws-config-to-hdf")
		require.NotNil(t, fp)
		assert.Equal(t, 0.0, fp.Fingerprint("not a map"))
	})
}
