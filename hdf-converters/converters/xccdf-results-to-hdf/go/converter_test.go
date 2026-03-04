package xccdf

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func fixtureDir() string {
	return filepath.Join(shared.GetConvertersDir(), "xccdf-results-to-hdf", "fixtures", "input")
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(), name))
	require.NoError(t, err, "Failed to read fixture %s", name)
	return data
}

// --- Error handling tests ---

func TestConvertXccdfResultsToHDF_EmptyInput(t *testing.T) {
	result, err := ConvertXccdfResultsToHDF([]byte{}, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertXccdfResultsToHDF_InvalidXML(t *testing.T) {
	result, err := ConvertXccdfResultsToHDF([]byte("not valid xml at all"), converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not an XCCDF or ARF")
}

func TestConvertXccdfResultsToHDF_NonXccdfXML(t *testing.T) {
	// Valid XML but not an XCCDF Benchmark - Go xml.Unmarshal rejects the
	// wrong root element name, so we get a parse-level error.
	input := []byte(`<?xml version="1.0"?><root><child>text</child></root>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "XCCDF")
}

func TestConvertXccdfResultsToHDF_WrongNamespaceXML(t *testing.T) {
	// XCCDF-like structure but wrong namespace - Go xml.Unmarshal rejects
	// the mismatched namespace, so we get a parse-level error.
	input := []byte(`<?xml version="1.0"?><Benchmark xmlns="http://wrong.namespace"><title>test</title></Benchmark>`)
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "XCCDF")
}

// --- Minimal fixture tests ---

func TestConvertXccdfResultsToHDF_Minimal(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Targets, 1)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "minimal.json", result)
}

func TestConvertXccdfResultsToHDF_MinimalRequirementCount(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 2, "minimal.xml has 2 rule-results")
}

func TestConvertXccdfResultsToHDF_MinimalStatusMapping(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First rule-result is "fail"
	failReq := findRequirementByIDRef(reqs, "xccdf_moc.elpmaxe.www_rule_1")
	require.NotNil(t, failReq, "Should find rule_1")
	assert.Equal(t, hdf.Failed, failReq.Results[0].Status)

	// Second rule-result is "pass"
	passReq := findRequirementByIDRef(reqs, "xccdf_moc.elpmaxe.www_rule_2")
	require.NotNil(t, passReq, "Should find rule_2")
	assert.Equal(t, hdf.Passed, passReq.Results[0].Status)
}

func TestConvertXccdfResultsToHDF_MinimalDefaultImpact(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml rules have no severity, so impact should default to 0.5
	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, 0.5, req.Impact, "No severity should default to 0.5 for %s", req.ID)
	}
}

func TestConvertXccdfResultsToHDF_MinimalIDFallback(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml rules have no <version>, so ID falls back to idref
	for _, req := range result.Baselines[0].Requirements {
		assert.Contains(t, req.ID, "xccdf_moc.elpmaxe.www_rule_",
			"ID should fall back to idref when no Rule version exists")
	}
}

func TestConvertXccdfResultsToHDF_MinimalTarget(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Targets, 1)
	assert.Equal(t, "Test Target", result.Targets[0].Name)
	assert.Equal(t, hdf.Host, result.Targets[0].Type)
	assert.Nil(t, result.Targets[0].IPAddress, "minimal.xml has no target-address")
}

func TestConvertXccdfResultsToHDF_MinimalTimestamp(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2012, result.Timestamp.Year())
	assert.Equal(t, 12, int(result.Timestamp.Month()))
	assert.Equal(t, 10, result.Timestamp.Day())
}

func TestConvertXccdfResultsToHDF_MinimalDuration(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics)
	require.NotNil(t, result.Statistics.Duration)
	// start-time and end-time are the same in minimal.xml
	assert.Equal(t, 0.0, *result.Statistics.Duration)
}

func TestConvertXccdfResultsToHDF_MinimalBaselineName(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// minimal.xml has no <title>, so baseline name falls back to Benchmark id
	assert.Equal(t, "xccdf_moc.elpmaxe.www_benchmark_test", result.Baselines[0].Name)
}

func TestConvertXccdfResultsToHDF_MinimalNoNIST(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		nist, ok := req.Tags["nist"]
		assert.True(t, ok, "nist tag should be present")
		nistSlice, ok := nist.([]string)
		assert.True(t, ok, "nist should be a string slice")
		assert.Empty(t, nistSlice, "No CCI idents means empty nist")
	}
}

// --- STIG RHEL7 fixture tests ---

func TestConvertXccdfResultsToHDF_StigRhel7(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Targets, 1)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "stig-rhel7.json", result)
}

func TestConvertXccdfResultsToHDF_StigRequirementCount(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 5, "stig-rhel7.xml has 5 rule-results")
}

func TestConvertXccdfResultsToHDF_StigBaselineName(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	assert.Equal(t, "Red Hat Enterprise Linux 7 Security Technical Implementation Guide",
		result.Baselines[0].Name)
}

func TestConvertXccdfResultsToHDF_StigSeverityToImpact(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// RHEL-07-010030: medium -> 0.5
	medReq := findRequirementByID(reqs, "RHEL-07-010030")
	require.NotNil(t, medReq, "Should find RHEL-07-010030")
	assert.Equal(t, 0.5, medReq.Impact, "medium severity should map to 0.5")

	// RHEL-07-010290: high -> 0.7
	highReq := findRequirementByID(reqs, "RHEL-07-010290")
	require.NotNil(t, highReq, "Should find RHEL-07-010290")
	assert.Equal(t, 0.7, highReq.Impact, "high severity should map to 0.7")

	// RHEL-07-020200: low -> 0.3
	lowReq := findRequirementByID(reqs, "RHEL-07-020200")
	require.NotNil(t, lowReq, "Should find RHEL-07-020200")
	assert.Equal(t, 0.3, lowReq.Impact, "low severity should map to 0.3")
}

func TestConvertXccdfResultsToHDF_StigStatusMapping(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// RHEL-07-010030: fail
	failReq := findRequirementByID(reqs, "RHEL-07-010030")
	require.NotNil(t, failReq)
	assert.Equal(t, hdf.Failed, failReq.Results[0].Status)

	// RHEL-07-010118: pass
	passReq := findRequirementByID(reqs, "RHEL-07-010118")
	require.NotNil(t, passReq)
	assert.Equal(t, hdf.Passed, passReq.Results[0].Status)
}

func TestConvertXccdfResultsToHDF_StigCCIToNIST(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirementByID(reqs, "RHEL-07-010030")
	require.NotNil(t, req, "Should find RHEL-07-010030")

	// Should have cci tag
	cciTag, ok := req.Tags["cci"]
	require.True(t, ok, "Should have cci tag")
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok, "cci should be a string slice")
	assert.Contains(t, cciSlice, "CCI-000048")

	// Should have nist tag derived from CCI
	nistTag, ok := req.Tags["nist"]
	require.True(t, ok, "Should have nist tag")
	nistSlice, ok := nistTag.([]string)
	require.True(t, ok, "nist should be a string slice")
	assert.NotEmpty(t, nistSlice, "NIST mapping should not be empty for CCI-000048")
}

func TestConvertXccdfResultsToHDF_StigTarget(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Targets, 1)
	target := result.Targets[0]
	assert.Equal(t, "localhost.localdomain", target.Name)
	assert.Equal(t, hdf.Host, target.Type)
	require.NotNil(t, target.IPAddress)
	assert.Equal(t, "127.0.0.1", *target.IPAddress)
}

func TestConvertXccdfResultsToHDF_StigDuration(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Statistics)
	require.NotNil(t, result.Statistics.Duration)
	// start-time 2021-12-17T10:39:29, end-time 2021-12-17T10:40:58 = 89 seconds
	assert.Equal(t, 89.0, *result.Statistics.Duration)
}

func TestConvertXccdfResultsToHDF_StigTimestamp(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2021, result.Timestamp.Year())
	assert.Equal(t, 12, int(result.Timestamp.Month()))
	assert.Equal(t, 17, result.Timestamp.Day())
}

func TestConvertXccdfResultsToHDF_StigDescriptions(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirementByID(reqs, "RHEL-07-010030")
	require.NotNil(t, req)

	// Should have at least "default" and "fix" descriptions
	require.GreaterOrEqual(t, len(req.Descriptions), 2)

	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc, "Should have default description")
	assert.NotEmpty(t, defaultDesc.Data, "Default description should not be empty")
	assert.Contains(t, defaultDesc.Data, "standardized and approved use notification")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc, "Should have fix description")
	assert.NotEmpty(t, fixDesc.Data, "Fix description should not be empty")
}

func TestConvertXccdfResultsToHDF_StigRuleVersionAsID(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// All STIG rules should use version text as ID
	expectedIDs := []string{
		"RHEL-07-010030",
		"RHEL-07-010060",
		"RHEL-07-010118",
		"RHEL-07-010290",
		"RHEL-07-020200",
	}
	for _, expectedID := range expectedIDs {
		req := findRequirementByID(reqs, expectedID)
		assert.NotNil(t, req, "Should find requirement with ID %s", expectedID)
	}
}

// --- Generator and DataSource tests ---

func TestConvertXccdfResultsToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertXccdfResultsToHDF_DataSource(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	require.NotNil(t, result.DataSource.Name)
	assert.Equal(t, "XCCDF", *result.DataSource.Name)
	require.NotNil(t, result.DataSource.Format)
	assert.Equal(t, "XCCDF", *result.DataSource.Format)
}

func TestConvertXccdfResultsToHDF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Len(t, checksum.Value, 64, "SHA-256 hex string should be 64 chars")
}

// --- Unit tests for internal helpers ---

func TestMapResultStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected hdf.ResultStatus
	}{
		{"pass", hdf.Passed},
		{"fail", hdf.Failed},
		{"error", hdf.Error},
		{"unknown", hdf.Error},
		{"notapplicable", hdf.NotApplicable},
		{"notchecked", hdf.NotReviewed},
		{"notselected", hdf.NotReviewed},
		{"informational", hdf.NotReviewed},
		{"fixed", hdf.Passed},
		{"PASS", hdf.Passed},
		{"Fail", hdf.Failed},
		{"bogus", hdf.Error},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapResultStatus(tt.input))
		})
	}
}

func TestExtractVulnDiscussion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with VulnDiscussion tags",
			input:    "<VulnDiscussion>Important security info</VulnDiscussion><other>ignored</other>",
			expected: "Important security info",
		},
		{
			name:     "no VulnDiscussion tags",
			input:    "Plain text description",
			expected: "Plain text description",
		},
		{
			name:     "empty VulnDiscussion",
			input:    "<VulnDiscussion></VulnDiscussion>",
			expected: "",
		},
		{
			name:     "VulnDiscussion with nested HTML",
			input:    "<VulnDiscussion>Info with <b>bold</b> text</VulnDiscussion>",
			expected: "Info with <b>bold</b> text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractVulnDiscussion(tt.input))
		})
	}
}

func TestSeverityToImpactMapping(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
		found    bool
	}{
		{"high", 0.7, true},
		{"medium", 0.5, true},
		{"low", 0.3, true},
		{"critical", 0.0, false},
		{"", 0.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			impact, ok := severityToImpact[tt.severity]
			assert.Equal(t, tt.found, ok)
			if ok {
				assert.Equal(t, tt.expected, impact)
			}
		})
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"empty", []string{}, nil},
		{"single", []string{"a"}, []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dedup(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- ARF fixture tests ---

func TestConvertARF_Minimal(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Targets, 1)

	// Should produce 1 requirement from 1 rule-result
	assert.Len(t, result.Baselines[0].Requirements, 1)

	// The rule-result is a "fail"
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "arf-minimal.json", result)
}

func TestConvertARF_AssetMetadata(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Targets, 1)
	target := result.Targets[0]

	// Target name from TestResult <target> element
	assert.Equal(t, "rh-hony", target.Name)
	assert.Equal(t, hdf.Host, target.Type)

	// IP address from TestResult target-address (first IPv4)
	require.NotNil(t, target.IPAddress)
	assert.Equal(t, "127.0.0.1", *target.IPAddress)

	// ARF asset enrichment: FQDN and hostname from computing-device
	require.NotNil(t, target.FQDN)
	assert.Equal(t, "rh-hony", *target.FQDN)

	// MAC address from ARF asset connections
	require.NotNil(t, target.MACAddress)
	assert.NotEmpty(t, *target.MACAddress)
}

func TestConvertARF_SkipsOVALReports(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// arf-minimal.xml has 2 reports: one XCCDF TestResult and one OVAL.
	// Only the XCCDF report should produce a baseline.
	assert.Len(t, result.Baselines, 1)
}

func TestConvertARF_BaselineName(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	// Baseline name from embedded Benchmark title
	assert.Equal(t, "Test Benchmark", result.Baselines[0].Name)
}

func TestConvertARF_DataSource(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	require.NotNil(t, result.DataSource.Name)
	assert.Equal(t, "ARF", *result.DataSource.Name)
	require.NotNil(t, result.DataSource.Format)
	assert.Equal(t, "ARF", *result.DataSource.Format)
}

func TestConvertARF_ResultsChecksum(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Len(t, checksum.Value, 64, "SHA-256 hex string should be 64 chars")
}

func TestConvertARF_Timestamp(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2021, result.Timestamp.Year())
	assert.Equal(t, 11, int(result.Timestamp.Month()))
	assert.Equal(t, 30, result.Timestamp.Day())
}

func TestConvertARF_Generator(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertARF_ExistingXccdfStillWorks(t *testing.T) {
	// Regression: raw XCCDF input must still work after adding ARF detection
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Baselines[0].Requirements, 5)
}

// --- Helper functions ---

func findRequirementByID(requirements []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}

// findRequirementByIDRef finds a requirement whose ID matches the given idref
// (used for minimal.xml where Rule IDs become the requirement IDs).
func findRequirementByIDRef(requirements []hdf.EvaluatedRequirement, idref string) *hdf.EvaluatedRequirement {
	for i := range requirements {
		if requirements[i].ID == idref {
			return &requirements[i]
		}
	}
	return nil
}

func findDescription(descriptions []hdf.Description, label string) *hdf.Description {
	for i := range descriptions {
		if descriptions[i].Label == label {
			return &descriptions[i]
		}
	}
	return nil
}

func TestConvertXccdfResultsToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}
