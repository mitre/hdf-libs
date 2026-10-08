package gitlab_vulnerabilities_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	"github.com/mitre/hdf-libs/hdf-converters/v3/registry/fptest"
)

func loadJSON(t *testing.T, path string) any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var parsed any
	require.NoError(t, json.Unmarshal(data, &parsed))
	return parsed
}

func TestGitlabVulnerabilitiesFingerprint(t *testing.T) {
	input := func(name string) any { return loadJSON(t, filepath.Join("..", "fixtures", "input", name)) }
	fptest.RunFingerprintTests(t, fptest.FingerprintSpec{
		ID:          "gitlab-vulnerabilities-to-hdf",
		Label:       "GitLab Vulnerability Report",
		Direction:   registry.DirectionIngest,
		InputFamily: registry.FamilyJSON,
		OutputType:  registry.OutputResults,
		Positive: []fptest.DetectionCase{
			{Name: "triaged envelope at confidence 1.0", Input: input("triaged.json"), Confidence: 1.0},
			{Name: "clean envelope (no nodes to inspect) at confidence 0.9", Input: input("clean.json"), Confidence: 0.9},
			{Name: "report-error envelope at confidence 0.9", Input: input("report-error.json"), Confidence: 0.9},
			{Name: "empty envelope at confidence 0.9", Input: input("empty.json"), Confidence: 0.9},
		},
		Negative: []fptest.DetectionCase{
			// The sibling CI-artifact report also has a vulnerabilities array.
			{Name: "gitlab CI artifact report", Input: loadJSON(t, filepath.Join("..", "..", "gitlab-to-hdf", "fixtures", "input", "multi-vuln.json"))},
			{Name: "empty object", Input: map[string]any{}},
			{Name: "vulnerabilities without a project block", Input: map[string]any{"vulnerabilities": []any{map[string]any{"uuid": "x", "state": "DETECTED"}}}},
			{Name: "project without fullPath", Input: map[string]any{"project": map[string]any{"id": "1"}, "vulnerabilities": []any{}}},
			{Name: "nodes without state", Input: map[string]any{"project": map[string]any{"fullPath": "g/p"}, "vulnerabilities": []any{map[string]any{"uuid": "x"}}}},
			{Name: "vulnerabilities not an array", Input: map[string]any{"project": map[string]any{"fullPath": "g/p"}, "vulnerabilities": map[string]any{}}},
		},
	})
}
