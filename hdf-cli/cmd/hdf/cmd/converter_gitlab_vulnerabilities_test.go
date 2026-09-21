package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitlabVulnerabilitiesConverter(t *testing.T) {
	runStandardConverterTests(t, converterTestCase{
		Source:         "gitlab-vulnerabilities",
		DisplayName:    "GitLab Vulnerability Report to HDF",
		FixtureDir:     "gitlab-vulnerabilities-to-hdf",
		MinimalFixture: "input/clean.json",
		ErrPrefix:      "gitlab-vulnerabilities conversion failed",
	})
}

// The CI-artifact report belongs to the sibling "gitlab" converter; the
// Vulnerability Report envelope must not accept it.
func TestGitlabVulnerabilitiesConverter_Convert_RejectsCIArtifactReport(t *testing.T) {
	converter, err := GetConverter("gitlab-vulnerabilities", "hdf")
	require.NoError(t, err)

	output, err := converter.Convert([]byte(`{"version":"15.0.0","vulnerabilities":[{"id":"x","name":"y"}]}`))
	assert.Error(t, err)
	assert.Nil(t, output)
}
