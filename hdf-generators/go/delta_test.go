package generators

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestBaseline(name string, reqs []hdf.BaselineRequirement) hdf.HDFBaseline {
	return hdf.HDFBaseline{
		Name:         name,
		Requirements: reqs,
	}
}

func makeTestReq(id string, title string) hdf.BaselineRequirement {
	return hdf.BaselineRequirement{
		ID:     id,
		Impact: 0.5,
		Title:  &title,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "Test requirement"},
		},
	}
}

func TestGenerateDelta_PreservesOldCode(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Updated title"),
	})
	links := []LinkRecord{
		{OldID: "V-001", NewID: "SV-001", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "primary"},
	}
	codeMap := map[string]string{
		"V-001": "  describe command('audit') do\n    its('stdout') { should match /enabled/ }\n  end",
	}

	result := GenerateDelta(baseline, links, codeMap, nil, 1)

	require.Len(t, result.Profile.Controls, 1)
	control := result.Profile.Controls["controls/SV-001.rb"]
	assert.Contains(t, control, "control 'SV-001' do")
	assert.Contains(t, control, "Updated title")
	assert.Contains(t, control, "describe command('audit')")
	assert.NotContains(t, control, "TODO")
}

func TestGenerateDelta_GeneratesStubForUnmatched(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-002", "New control"),
	})
	links := []LinkRecord{
		{NewID: "SV-002", MatchMethod: "none", Relationship: "no-match"},
	}

	result := GenerateDelta(baseline, links, map[string]string{}, nil, 0)

	control := result.Profile.Controls["controls/SV-002.rb"]
	assert.Contains(t, control, "TODO")
}

func TestGenerateDelta_RelatedUsesOldCode(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Primary control"),
		makeTestReq("SV-002", "Related control"),
	})
	links := []LinkRecord{
		{OldID: "V-001", NewID: "SV-001", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "primary"},
		{OldID: "V-001", NewID: "SV-002", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "related"},
	}
	codeMap := map[string]string{
		"V-001": "  describe service('sshd') do\n    it { should be_running }\n  end",
	}

	result := GenerateDelta(baseline, links, codeMap, nil, 1)

	require.Len(t, result.Profile.Controls, 2)
	assert.Contains(t, result.Profile.Controls["controls/SV-001.rb"], "describe service('sshd')")
	assert.Contains(t, result.Profile.Controls["controls/SV-002.rb"], "describe service('sshd')")
}

func TestGenerateDelta_Statistics(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "C1"),
		makeTestReq("SV-002", "C2"),
		makeTestReq("SV-003", "C3"),
	})
	links := []LinkRecord{
		{OldID: "V-001", NewID: "SV-001", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "primary"},
		{OldID: "V-001", NewID: "SV-002", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "related"},
		{NewID: "SV-003", MatchMethod: "none", Relationship: "no-match"},
	}

	result := GenerateDelta(baseline, links, map[string]string{"V-001": "# code"}, nil, 2)

	assert.Equal(t, 3, result.Statistics.NewControlsLength)
	assert.Equal(t, 2, result.Statistics.OldControlsLength)
	assert.Equal(t, 1, result.Statistics.Match)
	assert.Equal(t, 1, result.Statistics.DupMatch)
	assert.Equal(t, 1, result.Statistics.NoMatch)
	assert.Equal(t, 0, result.Statistics.PosMisMatch)
	assert.Equal(t, 2, result.Statistics.TotalMappedControls)
	// Verify invariant: totalMapped + noMatch = newControlsLength
	assert.Equal(t, result.Statistics.NewControlsLength,
		result.Statistics.TotalMappedControls+result.Statistics.NoMatch)
}

func TestGenerateDelta_EmptyMatchResult(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "C1"),
		makeTestReq("SV-002", "C2"),
	})

	result := GenerateDelta(baseline, nil, map[string]string{}, nil, 0)

	assert.Len(t, result.Profile.Controls, 2)
	assert.Equal(t, 2, result.Statistics.NewControlsLength)
	assert.Equal(t, 0, result.Statistics.Match)
}

func TestGenerateDelta_NoCodeOption(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "C1"),
	})
	links := []LinkRecord{
		{OldID: "V-001", NewID: "SV-001", MatchMethod: "exactId",
			Confidence: 1.0, Relationship: "primary"},
	}
	codeMap := map[string]string{"V-001": "  describe command('test') do\n  end"}

	result := GenerateDelta(baseline, links, codeMap, &DeltaOptions{NoCode: true}, 1)

	control := result.Profile.Controls["controls/SV-001.rb"]
	assert.Contains(t, control, "TODO")
	assert.NotContains(t, control, "describe command")
}

func TestGenerateDelta_SingleFile(t *testing.T) {
	baseline := makeTestBaseline("test-profile", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "C1"),
		makeTestReq("SV-002", "C2"),
	})

	result := GenerateDelta(baseline, nil, map[string]string{}, &DeltaOptions{SingleFile: true}, 0)

	require.Len(t, result.Profile.Controls, 1)
	content := result.Profile.Controls["controls/controls.rb"]
	assert.Contains(t, content, "control 'SV-001'")
	assert.Contains(t, content, "control 'SV-002'")
}

func TestGenerateDelta_InspecYml(t *testing.T) {
	title := "Updated STIG Profile"
	baseline := hdf.HDFBaseline{
		Name:         "updated-stig",
		Title:        &title,
		Requirements: []hdf.BaselineRequirement{makeTestReq("SV-001", "C1")},
	}

	result := GenerateDelta(baseline, nil, map[string]string{}, nil, 0)

	assert.Contains(t, result.Profile.InSpecYml, "name: updated-stig")
	assert.Contains(t, result.Profile.InSpecYml, "title: Updated STIG Profile")
}

func TestGenerateUpgrade_DropsUnmatchedCurrentByDefault(t *testing.T) {
	// Default behavior (KeepUnmatched=false): if a current requirement has
	// no upstream match (DISA dropped it), it's dropped from the output.
	// Matches SAF CLI delta semantics.
	current := makeTestBaseline("current", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Matched control"),
		makeTestReq("SV-099", "Deprecated control — no upstream match"),
	})
	upstream := makeTestBaseline("upstream", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Matched control (upstream)"),
	})
	links := []LinkRecord{
		{OldID: "SV-001", NewID: "SV-001", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "primary"},
	}

	result := GenerateUpgrade(current, upstream, links, &UpgradeOptions{})

	ids := make([]string, 0, len(result.Baseline.Requirements))
	for _, r := range result.Baseline.Requirements {
		ids = append(ids, r.ID)
	}
	assert.Contains(t, ids, "SV-001", "matched control should be present")
	assert.NotContains(t, ids, "SV-099", "unmatched current should be dropped by default")
}

func TestGenerateUpgrade_KeepUnmatched_PreservesUnmatchedCurrent(t *testing.T) {
	// With KeepUnmatched=true, unmatched current requirements survive the
	// upgrade. Useful for users carrying custom controls outside the DISA
	// STIG, or who want to inspect what got dropped before committing.
	current := makeTestBaseline("current", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Matched control"),
		makeTestReq("SV-099", "Deprecated control — no upstream match"),
	})
	upstream := makeTestBaseline("upstream", []hdf.BaselineRequirement{
		makeTestReq("SV-001", "Matched control (upstream)"),
	})
	links := []LinkRecord{
		{OldID: "SV-001", NewID: "SV-001", MatchMethod: "srgDeterministic",
			Confidence: 1.0, Relationship: "primary"},
	}

	result := GenerateUpgrade(current, upstream, links, &UpgradeOptions{KeepUnmatched: true})

	ids := make([]string, 0, len(result.Baseline.Requirements))
	for _, r := range result.Baseline.Requirements {
		ids = append(ids, r.ID)
	}
	assert.Contains(t, ids, "SV-001", "matched control should be present")
	assert.Contains(t, ids, "SV-099", "unmatched current should be preserved with --keep-unmatched")
}
