package netsparker

import (
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

func findDescription(descs []hdf.Description, label string) *hdf.Description {
	for i := range descs {
		if descs[i].Label == label {
			return &descs[i]
		}
	}
	return nil
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "netsparker-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertNetsparkerToHDF(input, testVersion) },
		MinimalFixture: "sample-netsparker-invicti.xml",
		InvalidInput:   "<not valid xml",
	})
}

// ---- Baseline structure ----

func TestConvertNetsparker_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
}

func TestConvertNetsparker_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	// Fixture has 3 unique vulnerabilities
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertNetsparker_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Netsparker Scan", result.Baselines[0].Name)
}

func TestConvertNetsparker_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	// Title should contain scan ID and URL
	assert.Contains(t, *result.Baselines[0].Title, "1eb9f18bfec849d2e438afb704b6a011")
	assert.Contains(t, *result.Baselines[0].Title, "https://foo.bar/")
}

func TestConvertNetsparker_Checksum(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertNetsparker_Generator(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "netsparker-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertNetsparker_Tool(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Contains(t, *result.Tool.Name, "Invicti")
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "XML", *result.Tool.Format)
}

// ---- Target ----

func TestConvertNetsparker_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "https://foo.bar/", result.Components[0].Name)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// ---- Requirement IDs use LookupId ----

func TestConvertNetsparker_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
}

// ---- Requirement title ----

func TestConvertNetsparker_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Weak Ciphers Enabled", *req.Title)
}

// ---- Severity → Impact ----

func TestConvertNetsparker_Severity(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Medium → 0.5
	medium := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	assert.InDelta(t, 0.5, medium.Impact, 0.001)

	// Low → 0.3
	low := shared.MustFindRequirement(t, reqs, "8d8e6052-221d-41c4-8f1e-af9704473901")
	assert.InDelta(t, 0.3, low.Impact, 0.001)
}

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"critical", 0.9},
		{"Critical", 0.9},
		{"high", 0.7},
		{"High", 0.7},
		{"medium", 0.5},
		{"Medium", 0.5},
		{"low", 0.3},
		{"Low", 0.3},
		{"best_practice", 0.0},
		{"information", 0.0},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

// ---- Dual NIST mapping: CWE + OWASP ----

func TestConvertNetsparker_DualNistMapping(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// First vuln: CWE-327 → SC-12/SC-13, OWASP A6 → CM-6
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
	// Should contain OWASP A6 mapping (CM-6) in addition to CWE mappings
	assert.Contains(t, nist, "CM-6", "should contain OWASP A6 -> CM-6 mapping")
}

// ---- Tags ----

func TestConvertNetsparker_Tags(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")

	// nist should be present
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist)
	assert.NotEmpty(t, nist)

	// cci should be present
	cciSlice := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cciSlice)
	assert.NotEmpty(t, cciSlice)

	// cweid should be present
	_, ok := req.Tags["cweid"]
	assert.True(t, ok, "cweid tag should be present")

	// owasp should be present
	_, ok = req.Tags["owasp"]
	assert.True(t, ok, "owasp tag should be present")
}

// ---- Descriptions ----

func TestConvertNetsparker_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")

	// Should have at least a default description
	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.NotEmpty(t, desc.Data)

	// Check description (from exploitation-skills/proof-of-concept)
	check := findDescription(req.Descriptions, "check")
	// check may be nil if exploitation-skills is empty (which it is for this vuln),
	// so we just ensure default exists

	// Fix description (from remedial-actions/remedial-procedure)
	fix := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fix, "expected a 'fix' description")
	assert.NotEmpty(t, fix.Data)
	_ = check
}

// ---- Status: all results Failed ----

func TestConvertNetsparker_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all Netsparker vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- CodeDesc contains HTTP request info ----

func TestConvertNetsparker_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)

	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "http-request")
	assert.Contains(t, codeDesc, "GET")
}

// ---- Message contains HTTP response info ----

func TestConvertNetsparker_Message(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)
	require.NotNil(t, req.Results[0].Message)
	assert.Contains(t, *req.Results[0].Message, "http-response")
}

// ---- StartTime from target initiated ----

func TestConvertNetsparker_StartTime(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "e8b418ae-a532-4b43-5d9b-af9b04bbbca3")
	require.NotEmpty(t, req.Results)

	// StartTime should be non-zero (parsed from target initiated)
	assert.False(t, req.Results[0].StartTime.IsZero(), "startTime should not be zero")
}

// ---- Netsparker root element detection ----

func TestConvertNetsparker_NetsparkerRootElement(t *testing.T) {
	// Test with netsparker-enterprise root element
	netsparkerXML := `<?xml version="1.0" encoding="utf-8" ?>
<netsparker-enterprise generated="03/07/2023 03:15 PM">
	<target>
		<scan-id>abc123</scan-id>
		<url>https://example.com/</url>
		<initiated>05/05/2023 04:57 PM</initiated>
	</target>
	<vulnerabilities>
		<vulnerability>
			<LookupId>test-id-1</LookupId>
			<url>https://example.com/</url>
			<type>TestVuln</type>
			<name>Test Vulnerability</name>
			<severity>High</severity>
			<certainty>100</certainty>
			<confirmed>True</confirmed>
			<state>Present</state>
			<classification>
				<owasp>A1</owasp>
				<cwe>89</cwe>
			</classification>
			<http-request>
				<method>GET</method>
				<content>GET / HTTP/1.1</content>
			</http-request>
			<http-response>
				<status-code>200</status-code>
				<duration>1</duration>
				<content>HTTP/1.1 200 OK</content>
			</http-response>
			<description>SQL Injection</description>
			<impact>Data loss</impact>
			<remedial-actions>Use parameterized queries</remedial-actions>
			<remedial-procedure>Fix the code</remedial-procedure>
		</vulnerability>
	</vulnerabilities>
</netsparker-enterprise>`

	result, err := ConvertNetsparkerToHDF([]byte(netsparkerXML), testVersion)
	require.NoError(t, err)

	// Tool name should be "Netsparker" for netsparker-enterprise root
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Netsparker", *result.Tool.Name)
}

func TestConvertNetsparkerToHDF_EmptyVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/empty.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "netsparker-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Invicti")
	assert.Contains(t, req.Results[0].CodeDesc, "https://clean.example.com/")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertNetsparkerToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertNetsparkerToHDF(input, testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "netsparker-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertNetsparkerToHDF(input, "0.1.0")
	})
}

func TestConvertNetsparker_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Netsparker resolves NIST tags via CWE and OWASP mappings (falling back
	// to DefaultStaticAnalysisNIST). At least one requirement should derive
	// a controlType.
	var sawDerivation bool
	for _, req := range reqs {
		if req.ControlType != nil {
			sawDerivation = true
			switch *req.ControlType {
			case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
			default:
				t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
			}
		}
	}
	assert.True(t, sawDerivation, "at least one Netsparker requirement should have a derived controlType")
}

func TestConvertNetsparker_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample-netsparker-invicti.xml")
	result, err := ConvertNetsparkerToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: Netsparker/Invicti is an automated DAST scanner", req.ID)
	}
}
