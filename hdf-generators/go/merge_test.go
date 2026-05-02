package generators

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

func strPtr(s string) *string { return &s }

func TestMergeRequirement_ScalarFieldsTakeUpstream(t *testing.T) {
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Title:  strPtr("Old title"),
		Impact: 0.5,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "Old description"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Title:  strPtr("New title"),
		Impact: 0.7,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "New description"},
		},
	}

	merged := MergeRequirement(current, upstream, "")

	assert.Equal(t, "SV-001", merged.ID, "ID should always come from upstream")
	assert.Equal(t, "New title", *merged.Title, "title should come from upstream by default")
	assert.Equal(t, 0.7, merged.Impact, "impact should come from upstream by default")
}

func TestMergeRequirement_CodePreservedFromCurrent(t *testing.T) {
	code := "  describe command('test') do\n  end"
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Impact: 0.5,
		Tags:   map[string]any{},
		Code:   &code,
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Impact: 0.7,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}

	merged := MergeRequirement(current, upstream, "")

	assert.NotNil(t, merged.Code, "code should be preserved from current")
	assert.Equal(t, code, *merged.Code)
}

func TestMergeRequirement_PreferCurrent_ScalarsFromCurrent(t *testing.T) {
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Title:  strPtr("Old title"),
		Impact: 0.5,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "Old description"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Title:  strPtr("New title"),
		Impact: 0.7,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "New description"},
		},
	}

	merged := MergeRequirement(current, upstream, "current")

	assert.Equal(t, "SV-001", merged.ID, "ID always comes from upstream")
	assert.Equal(t, "Old title", *merged.Title, "title should come from current with --prefer current")
	assert.Equal(t, 0.5, merged.Impact, "impact should come from current with --prefer current")
}

func TestMergeRequirement_PreferUpstream_CodeFromUpstream(t *testing.T) {
	oldCode := "  # old test"
	newCode := "  # new test"
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Impact: 0.5,
		Tags:   map[string]any{},
		Code:   &oldCode,
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Impact: 0.7,
		Tags:   map[string]any{},
		Code:   &newCode,
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}

	merged := MergeRequirement(current, upstream, "upstream")

	assert.NotNil(t, merged.Code)
	assert.Equal(t, newCode, *merged.Code, "code should come from upstream with --prefer upstream")
}

func TestMergeTags_UnionUpstreamWinsDefault(t *testing.T) {
	current := map[string]any{
		"cci":    []any{"CCI-000001"},
		"custom": "my-value",
		"gtitle": "Old SRG title",
	}
	upstream := map[string]any{
		"cci":     []any{"CCI-000001", "CCI-000002"},
		"gtitle":  "New SRG title",
		"stig_id": "RHEL-09-001234",
	}

	merged := MergeTags(current, upstream, "")

	assert.Contains(t, merged, "custom", "current-only keys should be preserved")
	assert.Equal(t, "my-value", merged["custom"])
	assert.Equal(t, "New SRG title", merged["gtitle"], "upstream should win on conflict")
	assert.Contains(t, merged, "stig_id", "upstream-only keys should be added")
	assert.Equal(t, upstream["cci"], merged["cci"], "upstream wins on key conflict")
}

func TestMergeTags_UnionCurrentWinsOnPreferCurrent(t *testing.T) {
	current := map[string]any{
		"cci":    []any{"CCI-000001"},
		"custom": "my-value",
		"gtitle": "Old SRG title",
	}
	upstream := map[string]any{
		"cci":     []any{"CCI-000001", "CCI-000002"},
		"gtitle":  "New SRG title",
		"stig_id": "RHEL-09-001234",
	}

	merged := MergeTags(current, upstream, "current")

	assert.Equal(t, "Old SRG title", merged["gtitle"], "current should win on conflict with --prefer current")
	assert.Equal(t, current["cci"], merged["cci"], "current should win on CCI conflict")
	assert.Contains(t, merged, "stig_id", "upstream-only keys should still be added")
}

func TestMergeTags_PreferUpstreamReplacesAll(t *testing.T) {
	current := map[string]any{
		"custom": "my-value",
		"gtitle": "Old SRG title",
	}
	upstream := map[string]any{
		"gtitle":  "New SRG title",
		"stig_id": "RHEL-09-001234",
	}

	merged := MergeTags(current, upstream, "upstream")

	assert.NotContains(t, merged, "custom", "current-only keys should be dropped with --prefer upstream")
	assert.Equal(t, "New SRG title", merged["gtitle"])
	assert.Equal(t, "RHEL-09-001234", merged["stig_id"])
}

func TestMergeDescriptions_UnionByLabelUpstreamWins(t *testing.T) {
	current := []hdf.Description{
		{Label: "default", Data: "Old default"},
		{Label: "check", Data: "Old check"},
		{Label: "custom", Data: "My custom desc"},
	}
	upstream := []hdf.Description{
		{Label: "default", Data: "New default"},
		{Label: "check", Data: "New check"},
		{Label: "fix", Data: "New fix"},
	}

	merged := MergeDescriptions(current, upstream, "")

	// Should have all unique labels: default, check, custom, fix
	labels := make(map[string]string)
	for _, d := range merged {
		labels[d.Label] = d.Data
	}
	assert.Len(t, labels, 4)
	assert.Equal(t, "New default", labels["default"], "upstream wins on label conflict")
	assert.Equal(t, "New check", labels["check"], "upstream wins on label conflict")
	assert.Equal(t, "My custom desc", labels["custom"], "current-only labels preserved")
	assert.Equal(t, "New fix", labels["fix"], "upstream-only labels added")
}

func TestMergeDescriptions_CurrentWinsOnPreferCurrent(t *testing.T) {
	current := []hdf.Description{
		{Label: "default", Data: "Old default"},
	}
	upstream := []hdf.Description{
		{Label: "default", Data: "New default"},
		{Label: "fix", Data: "New fix"},
	}

	merged := MergeDescriptions(current, upstream, "current")

	labels := make(map[string]string)
	for _, d := range merged {
		labels[d.Label] = d.Data
	}
	assert.Len(t, labels, 2)
	assert.Equal(t, "Old default", labels["default"], "current wins on conflict with --prefer current")
	assert.Equal(t, "New fix", labels["fix"], "upstream-only labels still added")
}

func TestMergeDescriptions_PreferUpstreamReplacesAll(t *testing.T) {
	current := []hdf.Description{
		{Label: "default", Data: "Old default"},
		{Label: "custom", Data: "My custom"},
	}
	upstream := []hdf.Description{
		{Label: "default", Data: "New default"},
		{Label: "fix", Data: "New fix"},
	}

	merged := MergeDescriptions(current, upstream, "upstream")

	labels := make(map[string]string)
	for _, d := range merged {
		labels[d.Label] = d.Data
	}
	assert.Len(t, labels, 2, "should only have upstream labels")
	assert.Equal(t, "New default", labels["default"])
	assert.Equal(t, "New fix", labels["fix"])
	assert.NotContains(t, labels, "custom", "current-only labels dropped with --prefer upstream")
}

func TestMergeRefs_UnionDeduplicated(t *testing.T) {
	url1 := "https://example.com/ref1"
	url2 := "https://example.com/ref2"
	url3 := "https://example.com/ref3"
	current := []hdf.Reference{
		{URL: &url1},
		{URL: &url2},
	}
	upstream := []hdf.Reference{
		{URL: &url2},
		{URL: &url3},
	}

	merged := MergeRefs(current, upstream, "")

	assert.Len(t, merged, 3, "should union and deduplicate by URL")
}

func TestMergeRefs_PreferCurrentKeepsCurrent(t *testing.T) {
	url1 := "https://example.com/ref1"
	url2 := "https://example.com/ref2"
	current := []hdf.Reference{{URL: &url1}}
	upstream := []hdf.Reference{{URL: &url2}}

	merged := MergeRefs(current, upstream, "current")

	assert.Len(t, merged, 1)
	assert.Equal(t, url1, *merged[0].URL)
}

func TestMergeRefs_PreferUpstreamKeepsUpstream(t *testing.T) {
	url1 := "https://example.com/ref1"
	url2 := "https://example.com/ref2"
	current := []hdf.Reference{{URL: &url1}}
	upstream := []hdf.Reference{{URL: &url2}}

	merged := MergeRefs(current, upstream, "upstream")

	assert.Len(t, merged, 1)
	assert.Equal(t, url2, *merged[0].URL)
}

func TestMergeRequirement_SeverityFromUpstream(t *testing.T) {
	high := hdf.SeverityHigh
	medium := hdf.Medium
	current := hdf.BaselineRequirement{
		ID:       "V-001",
		Impact:   0.5,
		Severity: &medium,
		Tags:     map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:       "SV-001",
		Impact:   0.7,
		Severity: &high,
		Tags:     map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}

	merged := MergeRequirement(current, upstream, "")

	assert.NotNil(t, merged.Severity)
	assert.Equal(t, hdf.SeverityHigh, *merged.Severity, "severity should come from upstream by default")
}

func TestMergeRequirement_NilCodeOnBothSides(t *testing.T) {
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Impact: 0.5,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Impact: 0.7,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}

	merged := MergeRequirement(current, upstream, "")

	assert.Nil(t, merged.Code, "code should be nil when neither side has code")
}

func TestMergeRequirement_SourceLocationFromUpstream(t *testing.T) {
	line := float64(42)
	ref := "controls/test.rb"
	current := hdf.BaselineRequirement{
		ID:     "V-001",
		Impact: 0.5,
		Tags:   map[string]any{},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}
	upstream := hdf.BaselineRequirement{
		ID:     "SV-001",
		Impact: 0.7,
		Tags:   map[string]any{},
		SourceLocation: &hdf.SourceLocation{
			Line: &line,
			Ref:  &ref,
		},
		Descriptions: []hdf.Description{
			{Label: "default", Data: "desc"},
		},
	}

	merged := MergeRequirement(current, upstream, "")

	assert.NotNil(t, merged.SourceLocation, "sourceLocation should come from upstream")
	assert.Equal(t, float64(42), *merged.SourceLocation.Line)
}
