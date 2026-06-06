package xccdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName: "xccdf-results-to-hdf",
		ConvertFn: func(input []byte) (interface{}, error) {
			return ConvertXccdfResultsToHDF(input, converterVersion)
		},
		MinimalFixture: "minimal.xml",
		InvalidInput:   "<not valid xml",
	})
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
	// XCCDF-like structure but wrong namespace
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
	assert.Len(t, result.Components, 1)

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

	require.Len(t, result.Components, 1)
	assert.Equal(t, "Test Target", result.Components[0].Name)
	assert.Equal(t, hdf.Host, result.Components[0].Type)
	assert.Nil(t, result.Components[0].IPAddress, "minimal.xml has no target-address")
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
	assert.Len(t, result.Components, 1)

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

func TestConvertXccdfResultsToHDF_StigControlType(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// At least one requirement should have a derived controlType once NIST
	// tags are present via CCI mapping. The exact distribution depends on
	// the source CCIs; this just verifies the pipeline plumbing works.
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			// Sanity check: must be one of the known classification values.
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one stig-rhel7 requirement should have a derived controlType")
}

func TestConvertXccdfResultsToHDF_StigSeverityToImpact(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// SV-204393: medium -> 0.5
	medReq := findRequirementByID(reqs, "SV-204393")
	require.NotNil(t, medReq, "Should find SV-204393")
	assert.Equal(t, 0.5, medReq.Impact, "medium severity should map to 0.5")

	// SV-204424: high -> 0.7
	highReq := findRequirementByID(reqs, "SV-204424")
	require.NotNil(t, highReq, "Should find SV-204424")
	assert.Equal(t, 0.7, highReq.Impact, "high severity should map to 0.7")

	// SV-204452: low -> 0.3
	lowReq := findRequirementByID(reqs, "SV-204452")
	require.NotNil(t, lowReq, "Should find SV-204452")
	assert.Equal(t, 0.3, lowReq.Impact, "low severity should map to 0.3")
}

func TestConvertXccdfResultsToHDF_StigStatusMapping(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// SV-204393: fail
	failReq := findRequirementByID(reqs, "SV-204393")
	require.NotNil(t, failReq)
	assert.Equal(t, hdf.Failed, failReq.Results[0].Status)

	// SV-204405: pass
	passReq := findRequirementByID(reqs, "SV-204405")
	require.NotNil(t, passReq)
	assert.Equal(t, hdf.Passed, passReq.Results[0].Status)
}

func TestConvertXccdfResultsToHDF_StigCCIToNIST(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := findRequirementByID(reqs, "SV-204393")
	require.NotNil(t, req, "Should find SV-204393")

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

	require.Len(t, result.Components, 1)
	target := result.Components[0]
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
	req := findRequirementByID(reqs, "SV-204393")
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
		"SV-204393",
		"SV-204396",
		"SV-204405",
		"SV-204424",
		"SV-204452",
	}
	for _, expectedID := range expectedIDs {
		req := findRequirementByID(reqs, expectedID)
		assert.NotNil(t, req, "Should find requirement with ID %s", expectedID)
	}
}

// --- Generator and Tool tests ---

func TestConvertXccdfResultsToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertXccdfResultsToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "XCCDF", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "XCCDF", *result.Tool.Format)
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
	// XCCDF uses standard severity levels via hdfutil.SeverityToImpact with default 0.5.
	tests := []struct {
		severity string
		expected float64
	}{
		{"high", 0.7},
		{"medium", 0.5},
		{"low", 0.3},
		{"critical", 0.9}, // Standard mapping (XCCDF doesn't use critical, but it's valid)
		{"", 0.5},         // Unknown/empty falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			assert.Equal(t, tt.expected, hdfutil.SeverityToImpact(tt.severity, 0.5))
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

func TestKebabCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"MS_Windows_Server_2022_STIG", "ms-windows-server-2022-stig"},
		{"simple", "simple"},
		{"UPPER_CASE", "upper-case"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, kebabCase(tt.input))
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
	assert.Len(t, result.Components, 1)

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

	require.Len(t, result.Components, 1)
	target := result.Components[0]

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

func TestConvertARF_Tool(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "ARF", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "ARF", *result.Tool.Format)
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

func TestConvertXccdfResultsToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

// --- XCCDF 1.1 namespace tests ---

func TestConvertXccdfResultsToHDF_XCCDF11Rejected(t *testing.T) {
	// XCCDF 1.1 benchmark without TestResult should error when calling
	// ConvertXccdfResultsToHDF (requires TestResult)
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no TestResult")
}

func TestConvertXccdfResultsToHDF_XCCDF12Rejected(t *testing.T) {
	// XCCDF 1.2 benchmark without TestResult should error when calling
	// ConvertXccdfResultsToHDF (requires TestResult)
	input := loadFixture(t, "benchmark-minimal-1.2.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "no TestResult")
}

// --- Benchmark-to-Baseline tests ---

func TestConvertXccdfBenchmarkToHDF_Minimal11(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "ms-windows-server-2022-stig", result.Name)
	require.NotNil(t, result.Title)
	assert.Equal(t, "Microsoft Windows Server 2022 Security Technical Implementation Guide", *result.Title)
	require.NotNil(t, result.Version)
	assert.Equal(t, "2", *result.Version)
	require.NotNil(t, result.Summary)
	assert.Contains(t, *result.Summary, "Security Technical Implementation Guide")

	assert.Len(t, result.Requirements, 3)
	assert.Len(t, result.Groups, 3)
}

func TestConvertXccdfBenchmarkToHDF_Minimal12(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.2.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should produce identical structure regardless of namespace
	assert.Equal(t, "ms-windows-server-2022-stig", result.Name)
	assert.Len(t, result.Requirements, 3)
}

func TestConvertXccdfBenchmarkToHDF_RequirementIDs(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	ids := make([]string, len(result.Requirements))
	for i, req := range result.Requirements {
		ids[i] = req.ID
	}

	// IDs should use Rule <version> text (STIG IDs)
	assert.Contains(t, ids, "SV-254238")
	assert.Contains(t, ids, "SV-254239")
	assert.Contains(t, ids, "SV-254240")
}

func TestConvertXccdfBenchmarkToHDF_SeverityMapping(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	reqMap := make(map[string]hdf.BaselineRequirement)
	for _, req := range result.Requirements {
		reqMap[req.ID] = req
	}

	// WN22-00-000010: medium -> 0.5
	assert.Equal(t, 0.5, reqMap["SV-254238"].Impact)
	// WN22-00-000030: high -> 0.7
	assert.Equal(t, 0.7, reqMap["SV-254240"].Impact)
}

func TestConvertXccdfBenchmarkToHDF_Descriptions(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	// Should have default, check, and fix descriptions
	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc)
	assert.Contains(t, defaultDesc.Data, "privileged account")
	assert.NotContains(t, defaultDesc.Data, "<VulnDiscussion>")

	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc)
	assert.Contains(t, checkDesc.Data, "administrative privileges")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc)
	assert.Contains(t, fixDesc.Data, "separate account")
}

func TestConvertXccdfBenchmarkToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	cciTag, ok := req.Tags["cci"]
	require.True(t, ok)
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok)
	assert.Contains(t, cciSlice, "CCI-000366")

	nistTag, ok := req.Tags["nist"]
	require.True(t, ok)
	nistSlice, ok := nistTag.([]string)
	require.True(t, ok)
	assert.NotEmpty(t, nistSlice)
}

func TestConvertXccdfBenchmarkToHDF_MultipleCCIs(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254239")
	require.NotNil(t, req)

	cciTag, ok := req.Tags["cci"]
	require.True(t, ok)
	cciSlice, ok := cciTag.([]string)
	require.True(t, ok)
	// WN22-00-000020 has 2 CCI idents
	assert.Len(t, cciSlice, 2)
	assert.Contains(t, cciSlice, "CCI-004066")
	assert.Contains(t, cciSlice, "CCI-000199")
}

func TestConvertXccdfBenchmarkToHDF_STIGTags(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)

	assert.Equal(t, "SV-254238r991589_rule", req.Tags["rid"])
	assert.Equal(t, "WN22-00-000010", req.Tags["stig_id"])
	assert.Equal(t, "medium", req.Tags["severity"])
	assert.Equal(t, "C-57723r848528_chk", req.Tags["check_id"])
	assert.Equal(t, "F-57674r848529_fix", req.Tags["fix_id"])
	assert.Equal(t, "V-254238", req.Tags["gid"])
	assert.Equal(t, "SRG-OS-000480-GPOS-00227", req.Tags["gtitle"])
}

func TestConvertXccdfBenchmarkToHDF_Groups(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.Len(t, result.Groups, 3)
	assert.Equal(t, "V-254238", result.Groups[0].ID)
	require.NotNil(t, result.Groups[0].Title)
	assert.Equal(t, "SRG-OS-000480-GPOS-00227", *result.Groups[0].Title)
	assert.Equal(t, []string{"SV-254238"}, result.Groups[0].Requirements)
}

func TestConvertXccdfBenchmarkToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "hdf-converters", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
}

func TestConvertXccdfBenchmarkToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Integrity)
	require.NotNil(t, result.Integrity.Algorithm)
	assert.Equal(t, hdf.Sha256, *result.Integrity.Algorithm)
	require.NotNil(t, result.Integrity.Checksum)
	assert.Len(t, *result.Integrity.Checksum, 64)
}

func TestConvertXccdfBenchmarkToHDF_ErrorOnResults(t *testing.T) {
	// Results documents should produce a helpful error message
	input := loadFixture(t, "stig-rhel7.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "TestResult")
	assert.Contains(t, err.Error(), "xccdf-results")
}

func TestConvertXccdfBenchmarkToHDF_EmptyInput(t *testing.T) {
	result, err := ConvertXccdfBenchmarkToHDF([]byte{}, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertXccdfBenchmarkToHDF_NonXccdfInput(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><root><child>text</child></root>`)
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "not an XCCDF")
}

func TestConvertXccdfBenchmarkToHDF_Severity(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	result, err := ConvertXccdfBenchmarkToHDF(input, converterVersion)
	require.NoError(t, err)

	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)
	require.NotNil(t, req.Severity)
	assert.Equal(t, hdf.SeverityMedium, *req.Severity)

	highReq := findBaselineRequirement(result.Requirements, "SV-254240")
	require.NotNil(t, highReq)
	require.NotNil(t, highReq.Severity)
	assert.Equal(t, hdf.SeverityHigh, *highReq.Severity)
}

// --- ConvertXccdfToHDF auto-detect tests ---

func TestConvertXccdfToHDF_AutoDetectBenchmark(t *testing.T) {
	input := loadFixture(t, "benchmark-minimal-1.1.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "baseline", outputType)
	assert.NotEmpty(t, output)

	// Verify it's valid baseline JSON
	var baseline hdf.HDFBaseline
	err = json.Unmarshal(output, &baseline)
	require.NoError(t, err)
	assert.Equal(t, "ms-windows-server-2022-stig", baseline.Name)
	assert.Len(t, baseline.Requirements, 3)
}

func TestConvertXccdfToHDF_AutoDetectResults(t *testing.T) {
	input := loadFixture(t, "stig-rhel7.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "results", outputType)
	assert.NotEmpty(t, output)

	// Verify it's valid results JSON
	var results hdf.HDFResults
	err = json.Unmarshal(output, &results)
	require.NoError(t, err)
	assert.Len(t, results.Baselines[0].Requirements, 5)
}

func TestConvertXccdfToHDF_AutoDetectARF(t *testing.T) {
	input := loadFixture(t, "arf-minimal.xml")
	output, outputType, err := ConvertXccdfToHDF(input, converterVersion)
	require.NoError(t, err)
	assert.Equal(t, "results", outputType)
	assert.NotEmpty(t, output)
}

func TestConvertXccdfToHDF_EmptyInput(t *testing.T) {
	_, _, err := ConvertXccdfToHDF([]byte{}, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty input")
}

func TestConvertXccdfToHDF_InvalidInput(t *testing.T) {
	_, _, err := ConvertXccdfToHDF([]byte("not xml"), converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an XCCDF")
}

// --- Full Win2022 STIG test (if file exists) ---

func TestConvertXccdfBenchmarkToHDF_FullWin2022STIG(t *testing.T) {
	// Test with full Win2022 STIG if available (283 requirements)
	stigPath := filepath.Join(shared.GetConvertersDir(), "..", "..", "U_MS_Windows_Server_2022_STIG_V2R7_Manual-xccdf.xml")
	data, err := os.ReadFile(stigPath)
	if err != nil {
		t.Skip("Full Win2022 STIG not available at expected path")
	}

	result, err := ConvertXccdfBenchmarkToHDF(data, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Win2022 STIG V2R7 has 283 groups/rules
	assert.Equal(t, 283, len(result.Requirements), "Win2022 STIG should have 283 requirements")
	assert.Equal(t, 283, len(result.Groups))
	assert.Equal(t, "ms-windows-server-2022-stig", result.Name)
	require.NotNil(t, result.Title)
	assert.Contains(t, *result.Title, "Windows Server 2022")

	// Spot-check first requirement
	req := findBaselineRequirement(result.Requirements, "SV-254238")
	require.NotNil(t, req)
	assert.Equal(t, 0.5, req.Impact)

	shared.WriteOutput(t, "xccdf-results-to-hdf", "win2022-stig-baseline.json", result)
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

func findBaselineRequirement(requirements []hdf.BaselineRequirement, id string) *hdf.BaselineRequirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}

// --- extractRuleID tests ---

func TestExtractRuleID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard STIG rule ID", "SV-254238r991589_rule", "SV-254238"},
		{"qualified XCCDF rule ID", "xccdf_mil.disa.stig_rule_SV-204393r603261_rule", "SV-204393"},
		{"lowercase sv prefix", "sv-12345r67_rule", "SV-12345"},
		{"no revision suffix", "SV-12345", "SV-12345"},
		{"non-SV rule ID passthrough", "xccdf_moc.elpmaxe.www_rule_1", "xccdf_moc.elpmaxe.www_rule_1"},
		{"empty string", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRuleID(tt.input))
		})
	}
}

func TestConvertXccdfResultsToHDF_EmptyRuleResults(t *testing.T) {
	input := loadFixture(t, "empty.xml")
	result, err := ConvertXccdfResultsToHDF(input, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "xccdf-results-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "XCCDF")
	assert.Contains(t, req.Results[0].CodeDesc, "empty-host.example.com")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertXccdfResultsToHDF_EmptyArfReport(t *testing.T) {
	arfXML := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1" xmlns:core="http://scap.nist.gov/schema/reporting-core/1.1">
  <arf:reports>
    <arf:report id="xccdf1">
      <arf:content>
        <TestResult xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_org.open-scap_testresult_default-profile" start-time="2021-11-30T13:51:50+01:00" end-time="2021-11-30T13:51:50+01:00">
          <title>OSCAP Scan Result</title>
          <target>arf-empty-host</target>
        </TestResult>
      </arf:content>
    </arf:report>
  </arf:reports>
</arf:asset-report-collection>`)
	result, err := ConvertXccdfResultsToHDF(arfXML, converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "xccdf-results-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "XCCDF")
	assert.Contains(t, req.Results[0].CodeDesc, "arf-empty-host")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTestsRaw(t, "xccdf-results-to-hdf", func(input []byte) ([]byte, error) {
		output, _, err := ConvertXccdfToHDF(input, "0.1.0")
		return output, err
	})
}

func findDescription(descriptions []hdf.Description, label string) *hdf.Description {
	for i := range descriptions {
		if descriptions[i].Label == label {
			return &descriptions[i]
		}
	}
	return nil
}
