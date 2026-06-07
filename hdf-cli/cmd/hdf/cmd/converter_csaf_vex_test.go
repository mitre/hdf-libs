package cmd

import (
	"os"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSAFVEXConverter_RegisteredAndProducesValidAmendments(t *testing.T) {
	converter, err := GetConverter("csaf-vex", "hdf")
	require.NoError(t, err)
	assert.Equal(t, "CSAF VEX to HDF Amendments", converter.Name())

	path := converterFixturePath(t, "csaf-vex-to-hdf", "input/sec-vex-2022-0001.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	output, err := converter.Convert(input)
	require.NoError(t, err)
	require.NotEmpty(t, output)

	docType, ok := detectHDFDocType(output)
	require.True(t, ok)
	assert.Equal(t, "amendments", docType)

	result := validators.ValidateAmendments(output)
	assert.True(t, result.Valid, "Amendments output must pass schema validation: %s", result.Error())
}

func TestCSAFVEXConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("csaf-vex", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "csaf-vex conversion failed")
}

func TestCSAFVEXConverter_EmptyActionableStatementsErrors(t *testing.T) {
	converter, err := GetConverter("csaf-vex", "hdf")
	require.NoError(t, err)

	path := converterFixturePath(t, "csaf-vex-to-hdf", "input/2022-evd-uc-01-ui-001.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	_, err = converter.Convert(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no actionable statements")
}
