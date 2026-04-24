package checkov

import (
	"testing"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFingerprint_SingleObject(t *testing.T) {
	input := `{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]},"summary":{"checkov_version":"3.2.524"}}`
	result := registry.DetectConverter([]byte(input))
	require.NotNil(t, result, "should detect checkov single object")
	assert.Equal(t, "checkov-to-hdf", result.Fingerprint.ID)
	assert.GreaterOrEqual(t, result.Confidence, 0.8)
}

func TestFingerprint_Array(t *testing.T) {
	input := `[{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[]},"summary":{"checkov_version":"3.2.524"}}]`
	result := registry.DetectConverter([]byte(input))
	require.NotNil(t, result, "should detect checkov array format")
	assert.Equal(t, "checkov-to-hdf", result.Fingerprint.ID)
	assert.GreaterOrEqual(t, result.Confidence, 0.8)
}

func TestFingerprint_NotCheckov(t *testing.T) {
	input := `{"Issues":[],"GosecVersion":"2.0"}`
	result := registry.DetectConverter([]byte(input))
	if result != nil {
		assert.NotEqual(t, "checkov-to-hdf", result.Fingerprint.ID)
	}
}

func TestFingerprint_NoResults(t *testing.T) {
	input := `{"check_type":"terraform"}`
	result := registry.DetectConverter([]byte(input))
	if result != nil {
		assert.NotEqual(t, "checkov-to-hdf", result.Fingerprint.ID)
	}
}
