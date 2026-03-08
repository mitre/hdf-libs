package generators

import (
	"strings"
	"testing"

	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
)

func makeRequirement(id string, impact float64) hdf.BaselineRequirement {
	return hdf.BaselineRequirement{
		ID:           id,
		Impact:       impact,
		Tags:         map[string]interface{}{},
		Descriptions: []hdf.Description{{Label: "default", Data: "Test requirement"}},
	}
}

func ptr(s string) *string { return &s }

func TestGenerateControlStub_Minimal(t *testing.T) {
	req := makeRequirement("SV-001", 0.5)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "control 'SV-001' do")
	assert.Contains(t, ruby, "impact 0.5")
	assert.Contains(t, ruby, "Test requirement")
	assert.True(t, strings.HasSuffix(ruby, "end\n"))
}

func TestGenerateControlStub_WithTitle(t *testing.T) {
	req := makeRequirement("SV-002", 0.5)
	req.Title = ptr("My Title")
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "title 'My Title'")
}

func TestGenerateControlStub_ImpactZero(t *testing.T) {
	req := makeRequirement("SV-003", 0.0)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 0.0")
	assert.NotContains(t, ruby, "impact 0\n")
}

func TestGenerateControlStub_ImpactOne(t *testing.T) {
	req := makeRequirement("SV-004", 1.0)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 1.0")
}

func TestGenerateControlStub_ImpactFractional(t *testing.T) {
	req := makeRequirement("SV-005", 0.7)
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "impact 0.7")
}

func TestGenerateControlStub_DefaultDescription(t *testing.T) {
	req := makeRequirement("SV-006", 0.5)
	req.Descriptions = []hdf.Description{{Label: "default", Data: "The main description"}}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "desc 'The main description'")
}

func TestGenerateControlStub_LabeledDescriptions(t *testing.T) {
	req := makeRequirement("SV-007", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main desc"},
		{Label: "check", Data: "Check this thing"},
		{Label: "fix", Data: "Fix this thing"},
	}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "desc 'check'")
	assert.Contains(t, ruby, "'Check this thing'")
	assert.Contains(t, ruby, "desc 'fix'")
	assert.Contains(t, ruby, "'Fix this thing'")
}

func TestGenerateControlStub_SkipDuplicateDefault(t *testing.T) {
	req := makeRequirement("SV-008", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main desc"},
		{Label: "default", Data: "Main desc"},
	}
	ruby := GenerateControlStub(req)
	count := strings.Count(ruby, "\n  desc ")
	assert.Equal(t, 1, count)
}

func TestGenerateControlStub_TagArrays(t *testing.T) {
	req := makeRequirement("SV-009", 0.5)
	req.Tags = map[string]interface{}{
		"cci":  []interface{}{"CCI-000068", "CCI-000197"},
		"nist": []interface{}{"AC-17 (2)", "IA-5 (1)"},
	}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag cci: ['CCI-000068', 'CCI-000197']")
	assert.Contains(t, ruby, "tag nist: ['AC-17 (2)', 'IA-5 (1)']")
}

func TestGenerateControlStub_TagString(t *testing.T) {
	req := makeRequirement("SV-010", 0.5)
	req.Tags = map[string]interface{}{"severity": "medium"}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag severity: 'medium'")
}

func TestGenerateControlStub_TagNil(t *testing.T) {
	req := makeRequirement("SV-011", 0.5)
	req.Tags = map[string]interface{}{"severity": nil}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag severity: nil")
}

func TestGenerateControlStub_TagBoolean(t *testing.T) {
	req := makeRequirement("SV-012", 0.5)
	req.Tags = map[string]interface{}{"documentable": false}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag documentable: false")
}

func TestGenerateControlStub_WithCode(t *testing.T) {
	req := makeRequirement("SV-013", 0.5)
	code := "  describe file(\"/etc/ssh/sshd_config\") do\n    it { should exist }\n  end"
	req.Code = &code
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, `describe file("/etc/ssh/sshd_config")`)
	assert.Contains(t, ruby, "it { should exist }")
}

func TestGenerateControlStub_StubComment(t *testing.T) {
	req := makeRequirement("SV-014", 0.5)
	ruby := GenerateControlStub(req)
	assert.Regexp(t, `(?i)# TODO|# Stub`, ruby)
}

func TestGenerateControlStub_EscapesDescriptions(t *testing.T) {
	req := makeRequirement("SV-015", 0.5)
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: `it's a "complex" description`},
	}
	ruby := GenerateControlStub(req)
	// Should not have unescaped single quote breaking Ruby
	assert.NotContains(t, ruby, "desc 'it's")
}

func TestGenerateControlStub_TagNumber(t *testing.T) {
	req := makeRequirement("SV-018", 0.5)
	req.Tags = map[string]interface{}{"weight": 10.0}
	ruby := GenerateControlStub(req)
	assert.Contains(t, ruby, "tag weight: 10")
}

func TestGenerateControlStub_WellFormedBlock(t *testing.T) {
	req := makeRequirement("SV-017", 0.5)
	req.Title = ptr("Test Control")
	req.Descriptions = []hdf.Description{
		{Label: "default", Data: "Main description"},
		{Label: "check", Data: "Verify the setting"},
	}
	req.Tags = map[string]interface{}{"nist": []interface{}{"AC-2"}, "severity": "medium"}
	ruby := GenerateControlStub(req)

	assert.True(t, strings.HasPrefix(ruby, "control 'SV-017' do\n"))
	assert.True(t, strings.HasSuffix(ruby, "end\n"))

	titleIdx := strings.Index(ruby, "title")
	descIdx := strings.Index(ruby, "desc '")
	impactIdx := strings.Index(ruby, "impact")
	tagIdx := strings.Index(ruby, "tag ")
	assert.Less(t, titleIdx, descIdx)
	assert.Less(t, descIdx, impactIdx)
	assert.Less(t, impactIdx, tagIdx)
}
