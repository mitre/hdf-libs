package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSonarqubeConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "sonarqube",
		DisplayName:    "SonarQube to HDF",
		FixtureDir:     "sonarqube-to-hdf",
		MinimalFixture: "input/minimal.json",
		ErrPrefix:      "sonarqube conversion failed",
	})
}

func TestSonarqubeConverter_Convert_InvalidStructure(t *testing.T) {
	converter, err := GetConverter("sonarqube", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(`{"not": "sonarqube"}`))
	assert.Error(t, err, "Should fail on invalid SonarQube structure")
	assert.Nil(t, output)
}
