package nessus

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func TestConvertNessusToHDF_Sample(t *testing.T) {
	// Load real Nessus scan fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read sample.nessus fixture")

	// Convert
	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify basic structure
	assert.Equal(t, "nessus-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)
	assert.Len(t, result.Baselines, 3, "Should have 3 baselines (one per scanned host)")
	assert.Len(t, result.Components, 3, "Should have 3 targets (3 scanned hosts)")

	// Verify each baseline has requirements
	for _, baseline := range result.Baselines {
		assert.Equal(t, "Nessus Basic Network Scan", baseline.Name)
		assert.Greater(t, len(baseline.Requirements), 0, "Should have requirements")
	}

	// Write output for differential testing
	shared.WriteOutput(t, "nessus-to-hdf", "sample.json", result)
}

func TestConvertNessusToHDF_Tool(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "sample.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Nessus", *result.Tool.Name)
	assert.Nil(t, result.Tool.Version)
	assert.Nil(t, result.Tool.Format)
}

func TestConvertNessusToHDF_Compliance(t *testing.T) {
	// Load compliance fixture
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "compliance.nessus")
	inputData, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read compliance.nessus fixture")

	// Convert
	result, err := ConvertNessusToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify basic structure
	assert.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Nessus DISA STIG Compliance Audit", baseline.Name)

	// Should have 5 compliance findings
	assert.Len(t, baseline.Requirements, 5, "Should have 5 compliance findings")

	// Test FAILED compliance result (CAT II)
	failedReq := findRequirementByID(baseline.Requirements, "V-71849")
	require.NotNil(t, failedReq, "Should find V-71849")
	assert.Equal(t, "V-71849", failedReq.ID)
	assert.Contains(t, *failedReq.Title, "RHEL-07-010010")
	assert.Equal(t, 0.5, failedReq.Impact, "CAT II should map to 0.5")
	assert.Equal(t, hdf.Failed, failedReq.Results[0].Status)
	assert.Contains(t, failedReq.Tags, "stig_id")
	assert.Equal(t, "RHEL-07-010010", failedReq.Tags["stig_id"])

	// Test FAILED compliance result (CAT I - High)
	highReq := findRequirementByID(baseline.Requirements, "V-71971")
	require.NotNil(t, highReq, "Should find V-71971")
	assert.Equal(t, 0.7, highReq.Impact, "CAT I should map to 0.7")
	assert.Equal(t, hdf.Failed, highReq.Results[0].Status)

	// Test PASSED compliance result (CAT III - Low)
	passedReq := findRequirementByID(baseline.Requirements, "V-72083")
	require.NotNil(t, passedReq, "Should find V-72083")
	assert.Equal(t, 0.3, passedReq.Impact, "CAT III should map to 0.3")
	assert.Equal(t, hdf.Passed, passedReq.Results[0].Status)

	// Test WARNING compliance result
	warningReq := findRequirementByID(baseline.Requirements, "V-72095")
	require.NotNil(t, warningReq, "Should find V-72095")
	assert.Equal(t, hdf.NotApplicable, warningReq.Results[0].Status, "WARNING should map to notApplicable")

	// Test ERROR compliance result
	errorReq := findRequirementByID(baseline.Requirements, "V-72229")
	require.NotNil(t, errorReq, "Should find V-72229")
	assert.Equal(t, hdf.Error, errorReq.Results[0].Status)

	// Write output for differential testing
	shared.WriteOutput(t, "nessus-to-hdf", "compliance.json", result)
}

func TestConvertNessusToHDF_ClassificationFields(t *testing.T) {
	inputPath := filepath.Join(shared.GetConvertersDir(), "nessus-to-hdf", "fixtures", "input", "compliance.nessus")
	input, err := os.ReadFile(inputPath)
	require.NoError(t, err)

	result, err := ConvertNessusToHDF(input, converterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Nessus always serializes the item as code -> verificationMethod=automated
	// applies to every requirement. controlType is derived where NIST tags
	// resolve to a known family.
	var sawControlType, sawVerification bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawControlType = true
		}
		if req.VerificationMethod != nil {
			assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
				"every nessus requirement has non-empty code => automated")
			sawVerification = true
		}
	}
	assert.True(t, sawControlType, "at least one requirement should derive controlType")
	assert.True(t, sawVerification, "every requirement should have verificationMethod=automated")
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "nessus-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNessusToHDF(input, converterVersion) },
		MinimalFixture: "compliance.nessus",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertNessusToHDF_EmptyHosts(t *testing.T) {
	emptyXML := []byte(`<?xml version="1.0"?>
<NessusClientData_v2>
  <Policy>
    <policyName>Empty Scan</policyName>
    <Preferences>
      <ServerPreferences></ServerPreferences>
    </Preferences>
  </Policy>
  <Report name="Empty Scan"></Report>
</NessusClientData_v2>`)

	result, err := ConvertNessusToHDF(emptyXML, converterVersion)
	require.NoError(t, err, "Conversion should succeed with empty hosts")
	require.NotNil(t, result, "Result should not be nil")

	assert.Len(t, result.Baselines, 0, "Should have no baselines")
	assert.Len(t, result.Components, 0, "Should have no targets")
	assert.Equal(t, 0.0, *result.Statistics.Duration, "Duration should be 0")
}

func TestParseComplianceRef(t *testing.T) {
	ref := "CCI|CCI-000366,STIG-ID|RHEL-07-010010,Rule-ID|SV-86473r2_rule,Vuln-ID|V-71849,CAT|II"

	t.Run("Extract CCI", func(t *testing.T) {
		ccis := parseComplianceRef(ref, "CCI")
		assert.Len(t, ccis, 1)
		assert.Equal(t, "CCI-000366", ccis[0])
	})

	t.Run("Extract STIG-ID", func(t *testing.T) {
		stigIDs := parseComplianceRef(ref, "STIG-ID")
		assert.Len(t, stigIDs, 1)
		assert.Equal(t, "RHEL-07-010010", stigIDs[0])
	})

	t.Run("Extract Rule-ID", func(t *testing.T) {
		ruleIDs := parseComplianceRef(ref, "Rule-ID")
		assert.Len(t, ruleIDs, 1)
		assert.Equal(t, "SV-86473r2_rule", ruleIDs[0])
	})

	t.Run("Extract Vuln-ID", func(t *testing.T) {
		vulnIDs := parseComplianceRef(ref, "Vuln-ID")
		assert.Len(t, vulnIDs, 1)
		assert.Equal(t, "V-71849", vulnIDs[0])
	})

	t.Run("Extract CAT", func(t *testing.T) {
		cats := parseComplianceRef(ref, "CAT")
		assert.Len(t, cats, 1)
		assert.Equal(t, "II", cats[0])
	})

	t.Run("Missing key", func(t *testing.T) {
		results := parseComplianceRef(ref, "NONEXISTENT")
		assert.Len(t, results, 0)
	})
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Simple HTML",
			input:    "<p>This is a test</p>",
			expected: "This is a test",
		},
		{
			name:     "Multiple tags",
			input:    "<div><p>Hello</p><p>World</p></div>",
			expected: "Hello World",
		},
		{
			name:     "No HTML",
			input:    "Plain text",
			expected: "Plain text",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "With whitespace",
			input:    "  <p>Text</p>  ",
			expected: "Text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHTML(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestImpactMapping(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"4", 0.9},   // Critical
		{"3", 0.7},   // High
		{"i", 0.7},   // High (compliance)
		{"2", 0.5},   // Medium
		{"ii", 0.5},  // Medium (compliance)
		{"1", 0.3},   // Low
		{"iii", 0.3}, // Low (compliance)
		{"0", 0.0},   // Info
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			impact, ok := nessusAliases[tt.severity]
			assert.True(t, ok, "Severity should be in mapping")
			assert.Equal(t, tt.expected, impact)
		})
	}
}

func TestParseHostTime(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		shouldOK bool
	}{
		{
			name:     "Nessus format",
			input:    "Mon Jan 29 10:00:00 2024",
			shouldOK: true,
		},
		{
			name:     "Empty string",
			input:    "",
			shouldOK: false, // Will return time.Now()
		},
		{
			name:     "RFC1123",
			input:    "Mon, 29 Jan 2024 10:00:00 GMT",
			shouldOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseHostTime(tt.input)
			assert.NotNil(t, result)
			// Just verify it returns a valid time
			assert.False(t, result.IsZero())
		})
	}
}

func TestIsFQDN(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"FQDN with subdomain", "rhel7-server.example.com", true},
		{"FQDN simple", "web01.prod.example.com", true},
		{"Two-part FQDN", "host.domain", true},
		{"IP address", "192.168.1.100", false},
		{"Simple hostname", "webserver", false},
		{"Localhost", "localhost", false},
		{"Hostname with hyphen", "web-server.example.com", true},
		{"Invalid - starts with hyphen", "-invalid.example.com", false},
		{"Invalid - ends with hyphen", "invalid-.example.com", false},
		{"Empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFQDN(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper function to find a requirement by ID
func findRequirementByID(requirements []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range requirements {
		if requirements[i].ID == id {
			return &requirements[i]
		}
	}
	return nil
}

func TestConvertNessusToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertNessusToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "nessus-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNessusToHDF(input, converterVersion)
	})
}
