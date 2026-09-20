package gitlab_vulnerabilities_to_hdf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A decision GitLab returned without any parseable time is dated at the fetch
// time in both language twins, never at a zero or epoch date.
func TestConvert_DecisionWithoutTimestamp_IsDatedAtFetchTime(t *testing.T) {
	var env map[string]any
	require.NoError(t, json.Unmarshal(readInput(t, "triaged.json"), &env))
	var kept []any
	for _, v := range env["vulnerabilities"].([]any) {
		node := v.(map[string]any)
		if node["id"] == "gid://gitlab/Vulnerability/1" {
			node["stateTransitions"] = map[string]any{"nodes": []any{}}
			node["dismissedAt"] = nil
			node["updatedAt"] = "not-a-time"
			node["detectedAt"] = ""
			node["latestDetectedPipeline"] = nil
			kept = append(kept, node)
		}
	}
	env["vulnerabilities"] = kept
	modified, err := json.Marshal(env)
	require.NoError(t, err)

	result, err := ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.NoError(t, err)
	req := requirementByGID(t, result, "1")
	require.Len(t, req.StatusOverrides, 1)
	assert.Equal(t, "2026-09-20T19:50:18Z", stamp(req.StatusOverrides[0].AppliedAt))
	assert.Equal(t, "2027-09-20T19:50:18Z", stamp(req.StatusOverrides[0].ExpiresAt))
	assert.Equal(t, "2026-09-20T19:50:18Z", stamp(req.Results[0].StartTime), "the result time takes the same fallback")
}
