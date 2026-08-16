package cmd

import (
	"os"
	"testing"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSPDXVEXConverter_RegisteredAndProducesValidAmendments(t *testing.T) {
	converter, err := GetConverter("spdx-vex", "hdf")
	require.NoError(t, err)
	assert.Equal(t, "SPDX VEX to HDF Amendments", converter.Name())

	path := converterFixturePath(t, "spdx-vex-to-hdf", "input/sample.spdx.json")
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

func TestSPDXVEXConverter_RejectsInvalidInput(t *testing.T) {
	converter, err := GetConverter("spdx-vex", "hdf")
	require.NoError(t, err)

	_, err = converter.Convert([]byte("not json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spdx-vex conversion failed")
}

func TestSPDXVEXConverter_NoActionableStatementsErrors(t *testing.T) {
	converter, err := GetConverter("spdx-vex", "hdf")
	require.NoError(t, err)

	path := converterFixturePath(t, "spdx-vex-to-hdf", "input/no-actionable.spdx.json")
	input, err := os.ReadFile(path)
	require.NoError(t, err)

	_, err = converter.Convert(input)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no actionable VEX statements")
}
