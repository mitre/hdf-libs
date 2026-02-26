//nolint:dupl // CLI converter test wrappers are structurally similar by design
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ensureGitlabRegistered() {
	conv := &gitlabConverter{}
	RegisterConverter("gitlab", "hdf", conv)
	RegisterConverter("gitlab-sast", "hdf", conv)
	RegisterConverter("gitlab-dast", "hdf", conv)
}

func TestGitlabConverter_IsRegistered(t *testing.T) {
	ensureGitlabRegistered()

	converter, err := GetConverter("gitlab", "hdf")
	require.NoError(t, err, "GitLab converter should be registered")
	assert.NotNil(t, converter, "Converter should not be nil")
	assert.Equal(t, "GitLab Security Report to HDF", converter.Name())
}

func TestGitlabConverter_SastAlias(t *testing.T) {
	ensureGitlabRegistered()

	converter, err := GetConverter("gitlab-sast", "hdf")
	require.NoError(t, err, "gitlab-sast alias should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "GitLab Security Report to HDF", converter.Name())
}

func TestGitlabConverter_DastAlias(t *testing.T) {
	ensureGitlabRegistered()

	converter, err := GetConverter("gitlab-dast", "hdf")
	require.NoError(t, err, "gitlab-dast alias should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "GitLab Security Report to HDF", converter.Name())
}

func TestGitlabConverter_Convert_MinimalSAST(t *testing.T) {
	ensureGitlabRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "gitlab-to-hdf", "input/minimal-sast.json"))
	require.NoError(t, err, "Failed to read minimal-sast.json fixture")

	converter, err := GetConverter("gitlab", "hdf")
	require.NoError(t, err, "Failed to get GitLab converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestGitlabConverter_Convert_MinimalDAST(t *testing.T) {
	ensureGitlabRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "gitlab-to-hdf", "input/minimal-dast.json"))
	require.NoError(t, err, "Failed to read minimal-dast.json fixture")

	converter, err := GetConverter("gitlab-sast", "hdf")
	require.NoError(t, err, "Failed to get gitlab-sast converter")

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "Conversion should succeed")
	require.NotEmpty(t, output, "Output should not be empty")

	assertHDFOutput(t, output)
}

func TestGitlabConverter_Convert_InvalidJSON(t *testing.T) {
	ensureGitlabRegistered()

	converter, err := GetConverter("gitlab", "hdf")
	require.NoError(t, err, "Failed to get GitLab converter")

	output, err := converter.Convert([]byte("not valid json"))
	assert.Error(t, err, "Should fail on invalid JSON")
	assert.Nil(t, output, "Output should be nil on error")
	assert.Contains(t, err.Error(), "gitlab conversion failed")
}

func TestGitlabConverter_Convert_EmptyInput(t *testing.T) {
	ensureGitlabRegistered()

	converter, err := GetConverter("gitlab", "hdf")
	require.NoError(t, err, "Failed to get GitLab converter")

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err, "Should fail on empty input")
	assert.Nil(t, output, "Output should be nil on error")
}
