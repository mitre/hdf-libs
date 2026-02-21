//nolint:dupl // Converter test files are intentionally structural mirrors of each other.
package cmd

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ensureJunitRegistered ensures the junit converter is registered.
func ensureJunitRegistered() {
	RegisterConverter("junit", "hdf", &junitConverter{})
}

func TestJunitConverter_IsRegistered(t *testing.T) {
	ensureJunitRegistered()

	converter, err := GetConverter("junit", "hdf")
	require.NoError(t, err, "junit converter should be registered")
	assert.NotNil(t, converter)
	assert.Equal(t, "JUnit to HDF", converter.Name())
}

func TestJunitConverter_Convert_Minimal(t *testing.T) {
	ensureJunitRegistered()

	inputData, err := os.ReadFile(converterFixturePath(t, "junit-to-hdf", "input/surefire-failing.xml"))
	require.NoError(t, err, "failed to read surefire-failing.xml fixture")

	converter, err := GetConverter("junit", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert(inputData)
	require.NoError(t, err, "conversion should succeed")
	require.NotEmpty(t, output)

	assertHDFOutput(t, output)
}

func TestJunitConverter_Convert_InvalidInput(t *testing.T) {
	ensureJunitRegistered()

	converter, err := GetConverter("junit", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte("not valid xml"))
	assert.Error(t, err)
	assert.Nil(t, output)
	assert.Contains(t, err.Error(), "junit conversion failed")
}

func TestJunitConverter_Convert_EmptyInput(t *testing.T) {
	ensureJunitRegistered()

	converter, err := GetConverter("junit", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(""))
	assert.Error(t, err)
	assert.Nil(t, output)
}
