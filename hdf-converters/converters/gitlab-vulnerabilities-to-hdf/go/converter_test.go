package gitlab_vulnerabilities_to_hdf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

func readInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func convertFixture(t *testing.T, name string) *hdf.HDFResults {
	t.Helper()
	result, err := ConvertGitlabVulnerabilitiesToHDF(readInput(t, name), testVersion)
	require.NoError(t, err)
	return result
}

// requirementByGID finds the requirement converted from the GitLab
// vulnerability with the given numeric id (the tail of its global id).
func requirementByGID(t *testing.T, result *hdf.HDFResults, id string) hdf.EvaluatedRequirement {
	t.Helper()
	want := "gid://gitlab/Vulnerability/" + id
	for _, b := range result.Baselines {
		for _, r := range b.Requirements {
			if gid, ok := r.Tags["gitlab/id"].(string); ok && gid == want {
				return r
			}
		}
	}
	t.Fatalf("no requirement carries gitlab/id %s", want)
	return hdf.EvaluatedRequirement{}
}

// Finding 50 ("Use of hard-coded credentials") was dismissed as FALSE_POSITIVE
// in GitLab. Raw status must stay what the scanner reported; the human decision
// rides as an attributed, expiring override and the computed effective posture.
func TestConvert_DismissedFalsePositive_KeepsRawFailedAndEmitsFalsePositiveOverride(t *testing.T) {
	req := requirementByGID(t, convertFixture(t, "triaged.json"), "50")

	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	require.Len(t, req.StatusOverrides, 1)
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.FalsePositive, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.NotApplicable, *o.Status)
	assert.Equal(t, "The flagged value is a documented demo credential, not a real secret.", o.Reason)
	assert.Equal(t, hdf.Username, o.AppliedBy.Type)
	assert.Equal(t, "sec-reviewer", o.AppliedBy.Identifier)
	assert.Equal(t, "2026-09-20T19:27:19Z", o.AppliedAt.UTC().Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, o.AppliedAt.AddDate(1, 0, 0), o.ExpiresAt)
	assert.Nil(t, o.Justification)
	require.Len(t, o.ExternalReferences, 1)
	assert.Equal(t, "GitLab Vulnerability Report", o.ExternalReferences[0].SourceName)
	require.NotNil(t, o.ExternalReferences[0].Href)
	assert.True(t, strings.HasSuffix(*o.ExternalReferences[0].Href, "/-/security/vulnerabilities/50"))

	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.FalsePositive, *req.Disposition)
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)

	assert.Equal(t, "DISMISSED", req.Tags["gitlab/state"])
	assert.Equal(t, "FALSE_POSITIVE", req.Tags["gitlab/dismissalReason"])
}
