package gitlab_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", name))
	require.NoError(t, err)
	return data
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "gitlab-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertGitlabToHDF(input, testVersion) },
		MinimalFixture: "minimal-dast.json",
	})
}

func TestConvertGitlabToHDF_EmptyVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "gitlab-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "GitLab")
	assert.Contains(t, req.Results[0].CodeDesc, "Semgrep")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

func TestConvertGitlabToHDF_MinimalSAST_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Equal(t, "gitlab-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

func TestConvertGitlabToHDF_MinimalSAST_Baseline(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	baseline := result.Baselines[0]
	assert.Equal(t, "GitLab Security Scan", baseline.Name)
	assert.Equal(t, "GitLab SAST Security Scan", *baseline.Title)
	assert.Equal(t, "Scanner: Semgrep v1.34.0", *baseline.Summary)
}

func TestConvertGitlabToHDF_MinimalSAST_Requirement(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "a1b2c3d4-e5f6-7890-abcd-ef1234567890", req.ID)
	assert.Equal(t, "SQL Injection", *req.Title)
	assert.InDelta(t, 0.9, req.Impact, 0.001)
}

func TestConvertGitlabToHDF_MinimalSAST_Result(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	assert.Equal(t, "File: src/db/queries.py | Line: 42 | Class: UserRepository | Method: find_by_name", req.Results[0].CodeDesc)
}

func TestConvertGitlabToHDF_MinimalSAST_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Descriptions, 2)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Contains(t, req.Descriptions[0].Data, "SQL query without sanitization")
	assert.Equal(t, "check", req.Descriptions[1].Label)
	assert.Contains(t, req.Descriptions[1].Data, "parameterized queries")
}

func TestConvertGitlabToHDF_MinimalSAST_Tags(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	nist := req.Tags["nist"]
	assert.NotNil(t, nist)

	// CWE tag should contain "89"
	cweTag := req.Tags["cwe"]
	assert.NotNil(t, cweTag)
	cweSlice, ok := cweTag.([]interface{})
	require.True(t, ok)
	assert.Contains(t, cweSlice, "89")
}

func TestConvertGitlabToHDF_MinimalSAST_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	checksum := result.Baselines[0].ResultsChecksum
	require.NotNil(t, checksum)
	assert.Equal(t, hdf.Sha256, checksum.Algorithm)
	assert.Len(t, checksum.Value, 64)
}

func TestConvertGitlabToHDF_MinimalSAST_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Semgrep", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
	assert.Equal(t, "1.34.0", *result.Tool.Version)
}

func TestConvertGitlabToHDF_MinimalSAST_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	assert.NotNil(t, result.Timestamp)
}

func TestConvertGitlabToHDF_MinimalSAST_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, hdf.Repository, result.Components[0].Type)
}

func TestConvertGitlabToHDF_MinimalDAST_Baseline(t *testing.T) {
	input := loadFixture(t, "input/minimal-dast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "GitLab DAST Security Scan", *result.Baselines[0].Title)
}

func TestConvertGitlabToHDF_MinimalDAST_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal-dast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "URL: https://app.example.com/search | Method: GET | Param: q", req.Results[0].CodeDesc)
}

func TestConvertGitlabToHDF_MinimalDAST_Impact(t *testing.T) {
	input := loadFixture(t, "input/minimal-dast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	assert.InDelta(t, 0.7, result.Baselines[0].Requirements[0].Impact, 0.001)
}

func TestConvertGitlabToHDF_MinimalDAST_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal-dast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

func TestConvertGitlabToHDF_MultiVuln_Count(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertGitlabToHDF_MultiVuln_SeverityMapping(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		switch req.ID {
		case "11111111-1111-1111-1111-111111111111":
			assert.InDelta(t, 0.9, req.Impact, 0.001, "Critical should map to 0.9")
		case "22222222-2222-2222-2222-222222222222":
			assert.InDelta(t, 0.5, req.Impact, 0.001, "Medium should map to 0.5")
		case "33333333-3333-3333-3333-333333333333":
			assert.InDelta(t, 0.0, req.Impact, 0.001, "Info should map to 0.0")
		}
	}
}

func TestConvertGitlabToHDF_MultiVuln_Identifiers(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		if req.ID == "11111111-1111-1111-1111-111111111111" {
			cweTag := req.Tags["cwe"]
			require.NotNil(t, cweTag)
			cweSlice, ok := cweTag.([]interface{})
			require.True(t, ok)
			assert.Contains(t, cweSlice, "78")

			cveTag := req.Tags["cve"]
			require.NotNil(t, cveTag)
			cveSlice, ok := cveTag.([]interface{})
			require.True(t, ok)
			assert.Contains(t, cveSlice, "CVE-2024-1234")
		}
	}
}

func TestConvertGitlabToHDF_MultiVuln_DefaultNIST(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	// Third vulnerability has no identifiers, should get default NIST
	for _, req := range result.Baselines[0].Requirements {
		if req.ID == "33333333-3333-3333-3333-333333333333" {
			nist := req.Tags["nist"]
			require.NotNil(t, nist)
			nistSlice, ok := nist.([]interface{})
			require.True(t, ok)
			assert.Contains(t, nistSlice, "SA-11")
			assert.Contains(t, nistSlice, "RA-5")
		}
	}
}

func TestConvertGitlabToHDF_MultiVuln_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		switch req.ID {
		case "11111111-1111-1111-1111-111111111111":
			assert.Equal(t, "File: src/utils/exec.py | Line: 15-18", req.Results[0].CodeDesc)
		case "22222222-2222-2222-2222-222222222222":
			assert.Equal(t, "File: src/api/handler.py | Line: 100-105 | Class: RequestHandler | Method: process", req.Results[0].CodeDesc)
		}
	}
}

func TestConvertGitlabToHDF_Serializable(t *testing.T) {
	input := loadFixture(t, "input/minimal-sast.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	output, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)
	assert.NotEmpty(t, output)

	// Verify it round-trips
	var parsed hdf.HDFResults
	err = json.Unmarshal(output, &parsed)
	require.NoError(t, err)
	assert.Equal(t, "gitlab-to-hdf", parsed.Generator.Name)
}

func Test_severityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"Critical", 0.9},
		{"High", 0.7},
		{"Medium", 0.5},
		{"Low", 0.3},
		{"Info", 0.0},
		{"Unknown", 0.5},
		{"", 0.5},
		{"critical", 0.9},
		{"HIGH", 0.7},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, severityToImpact(tc.severity), 0.001)
		})
	}
}

func Test_scanTypeLabel(t *testing.T) {
	assert.Equal(t, "SAST", scanTypeLabel("sast"))
	assert.Equal(t, "DAST", scanTypeLabel("dast"))
	assert.Equal(t, "Dependency Scanning", scanTypeLabel("dependency_scanning"))
	assert.Equal(t, "Container Scanning", scanTypeLabel("container_scanning"))
	assert.Equal(t, "Secret Detection", scanTypeLabel("secret_detection"))
	assert.Equal(t, "CUSTOM", scanTypeLabel("custom"))
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "gitlab-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertGitlabToHDF(input, "1.0.0")
	})
}

// Ground-truth anchor: the converter emits one requirement per top-level
// vulnerabilities[] entry. The source count is derived independently of the
// converter's parser (shared/go/anchor.go), so a silent under-extraction fails
// even when Go/TS golden parity agrees.
func TestConvertGitlabToHDF_VulnerabilitiesAnchor(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "vulnerabilities"),
		"multi-vuln.json: one requirement per vulnerabilities[]")
}

func TestConvertGitlabToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

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
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestConvertGitlabToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/multi-vuln.json")
	result, err := ConvertGitlabToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	for _, baseline := range result.Baselines {
		for _, req := range baseline.Requirements {
			require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
			assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
				"requirement %q should be marked automated", req.ID)
		}
	}
}

// GitLab carries no literal source snippet, so requirement.code holds the whole
// vulnerability object serialized as indented JSON. Pin that it is set on every
// requirement and round-trips byte-structurally back to the source vulnerability
// object across all scan-type fixtures (Heimdall CODE-tab fidelity). This also
// proves the many dropped fields (links, identifiers[].url, remediation linkage,
// location detail) survive into code.
func TestConvertGitlabToHDF_RequirementCode(t *testing.T) {
	for _, name := range []string{"minimal-dast.json", "minimal-sast.json", "multi-vuln.json"} {
		t.Run(name, func(t *testing.T) {
			input := loadFixture(t, "input/"+name)
			result, err := ConvertGitlabToHDF(input, testVersion)
			require.NoError(t, err)

			var raw struct {
				Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
			}
			require.NoError(t, json.Unmarshal(input, &raw))

			reqs := result.Baselines[0].Requirements
			require.Len(t, reqs, len(raw.Vulnerabilities))

			for i, req := range reqs {
				require.NotNilf(t, req.Code, "requirement %d: Code is nil; Heimdall CODE tab would be empty", i)

				var got, want interface{}
				require.NoErrorf(t, json.Unmarshal([]byte(*req.Code), &got), "requirement %d: Code is not valid JSON", i)
				require.NoError(t, json.Unmarshal(raw.Vulnerabilities[i], &want))
				assert.Equalf(t, want, got, "requirement %d: Code does not round-trip to source vulnerability object", i)

				// url fields that the typed struct/tags path drops must survive into code.
				assert.Contains(t, *req.Code, "\n", "requirement %d: Code should be indented JSON", i)
			}
		})
	}
}

// buildVulnCode has three branches: populated raw (indented JSON), empty raw,
// and malformed raw (json.Indent error). The last two are defensive and
// unreachable via the normal parse path, so exercise them directly.
func TestBuildVulnCode_Branches(t *testing.T) {
	// Populated raw: indented JSON that round-trips to the source object.
	source := []byte(`{"id":"x","severity":"High","links":[{"url":"https://example.com"}]}`)
	var vuln GitLabVulnerability
	require.NoError(t, json.Unmarshal(source, &vuln))
	code := buildVulnCode(vuln)
	assert.Contains(t, code, "\n  ", "expected indented JSON")
	var got, want interface{}
	require.NoError(t, json.Unmarshal([]byte(code), &got))
	require.NoError(t, json.Unmarshal(source, &want))
	assert.Equal(t, want, got)

	// Empty raw: defensive fallback.
	assert.Equal(t, "{}", buildVulnCode(GitLabVulnerability{}))

	// Malformed raw: json.Indent error fallback.
	assert.Equal(t, "{}", buildVulnCode(GitLabVulnerability{raw: json.RawMessage("{not json")}))
}

// UnmarshalJSON captures the raw bytes and delegates typed decoding; a type
// mismatch in the vulnerability propagates the decode error (exercised via the
// report-level parse, which surfaces as an invalid-JSON conversion failure).
func TestGitLabVulnerability_UnmarshalJSON_Error(t *testing.T) {
	var vuln GitLabVulnerability
	// id is typed string; a numeric id forces the inner json.Unmarshal to error.
	assert.Error(t, vuln.UnmarshalJSON([]byte(`{"id": 12345}`)))

	_, err := ConvertGitlabToHDF([]byte(`{"vulnerabilities":[{"id": 12345}]}`), testVersion)
	assert.Error(t, err)
}
