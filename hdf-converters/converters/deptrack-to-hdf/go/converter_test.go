package deptrack

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
		ConverterName:  "deptrack-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertDeptrackToHDF(input, testVersion) },
		MinimalFixture: "fpf-default.json",
	})
}

// ---- Default fixture: baseline structure ----

func TestConvertDeptrack_ControlType(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
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

func TestConvertDeptrack_Default(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	// fpf-default.json has 2 findings with unique matrix IDs
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestConvertDeptrack_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Dependency-Track Scan", result.Baselines[0].Name)
}

func TestConvertDeptrack_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "Acme Example")
}

func TestConvertDeptrack_Checksum(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertDeptrack_Generator(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "deptrack-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertDeptrack_Tool(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Dependency-Track", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "FPF", *result.Tool.Format)
}

// ---- Target ----

func TestConvertDeptrack_Target(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "Acme Example", result.Components[0].Name)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// ---- Severity → Impact mapping ----

func TestConvertDeptrack_SeverityLow(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Both findings in fpf-default.json are LOW severity
	for _, req := range reqs {
		assert.InDelta(t, 0.3, req.Impact, 0.001)
	}
}

func TestConvertDeptrack_SeverityInfo(t *testing.T) {
	input := loadFixture(t, "input/fpf-info-vulnerability.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1)
	// INFO severity → impact 0.0
	assert.InDelta(t, 0.0, reqs[0].Impact, 0.001)
}

// ---- CWE → NIST mapping ----

func TestConvertDeptrack_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// CWE-400 should have a NIST mapping
	nist := hdfutil.SafeStringSlice(reqs[0].Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

// ---- Requirement ID uses matrix field ----

func TestConvertDeptrack_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	shared.MustFindRequirement(t, reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
}

// ---- Requirement title includes purl and vuln title ----

func TestConvertDeptrack_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "pkg:npm/timespan@2.3.0")
	assert.Contains(t, *req.Title, "Regular Expression Denial of Service")
}

// ---- Descriptions: check and fix ----

func TestConvertDeptrack_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")

	checkDesc := findDescription(req.Descriptions, "check")
	require.NotNil(t, checkDesc, "expected a 'check' description")
	assert.Contains(t, checkDesc.Data, "timespan")

	fixDesc := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fixDesc, "expected a 'fix' description")
	assert.Contains(t, fixDesc.Data, "No direct patch")

	defaultDesc := findDescription(req.Descriptions, "default")
	require.NotNil(t, defaultDesc, "expected a 'default' description")
}

// ---- Status: all results are Failed ----

func TestConvertDeptrack_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all findings should be Failed (req %s)", req.ID)
		}
	}
}

// ---- Tags: NIST/CCI retained, scoring moved to structured fields ----

func TestConvertDeptrack_Tags(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	req := reqs[0]

	// nist
	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist should be present")
	assert.NotEmpty(t, nist)

	// cci
	cci := hdfutil.SafeStringSlice(req.Tags["cci"])
	require.NotNil(t, cci, "cci should be present")
	assert.NotEmpty(t, cci)

	// cweIds tag is retired — CWE now lives in the first-class cwe[] field.
	_, hasCweIds := req.Tags["cweIds"]
	assert.False(t, hasCweIds, "cweIds tag should be removed (moved to cwe[])")
}

// ---- CWE → first-class requirement.cwe[] ----

func TestConvertDeptrack_CweField(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	// Both findings carry cwes:[{cweId:400}] → cwe:["CWE-400"].
	for _, req := range result.Baselines[0].Requirements {
		assert.Equal(t, []string{"CWE-400"}, req.Cwe, "req %q should carry CWE-400 in cwe[]", req.ID)
	}
}

// getCweIDs / cwe[] empty-branch: a finding with no cwes emits no cwe[].
func TestConvertDeptrack_CweField_Absent(t *testing.T) {
	input := []byte(`{"meta":{},"project":{"uuid":"p1","name":"t"},"findings":[{"component":{"name":"c"},"vulnerability":{"severity":"LOW"},"matrix":"m1"}]}`)
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Cwe, "no cwes in source → cwe[] omitted")
	_, hasCve := req.Tags["cve"]
	assert.False(t, hasCve, "no aliases in source → tags.cve omitted")
}

// ---- CVE → tags.cve (from aliases[].cveId; the id is a UUID composite) ----

func TestConvertDeptrack_CveTag(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	// Finding 1 (timespan) has no aliases → no tags.cve.
	first := shared.MustFindRequirement(t, result.Baselines[0].Requirements,
		"ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46")
	_, hasCve := first.Tags["cve"]
	assert.False(t, hasCve, "finding without aliases should have no tags.cve")

	// Finding 2 (uglify-js) has aliases[0].cveId = CVE-2022-2053.
	second := shared.MustFindRequirement(t, result.Baselines[0].Requirements,
		"ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3")
	assert.Equal(t, []string{"CVE-2022-2053"}, hdfutil.SafeStringSlice(second.Tags["cve"]))
	assert.NotContains(t, second.Cwe, "CVE-2022-2053", "CVE must not leak into cwe[]")
}

// getCVEs branches: empty cveId skipped, duplicate cveId deduped.
func TestGetCVEs_Branches(t *testing.T) {
	assert.Nil(t, getCVEs(DeptrackVulnerability{}), "no aliases → nil")
	assert.Nil(t, getCVEs(DeptrackVulnerability{Aliases: []DeptrackAlias{{CveID: ""}}}),
		"empty cveId is skipped")
	assert.Equal(t, []string{"CVE-2021-44228"},
		getCVEs(DeptrackVulnerability{Aliases: []DeptrackAlias{
			{CveID: "CVE-2021-44228"}, {CveID: "CVE-2021-44228"}, {CveID: ""},
		}}), "duplicates deduped, empties dropped")
}

// ---- No vulnerabilities fixture ----

func TestConvertDeptrack_NoVulnerabilities(t *testing.T) {
	input := loadFixture(t, "input/fpf-no-vulnerabilities.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "deptrack-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "zero vulnerable components")
	assert.Equal(t, "laravel", result.Components[0].Name)
}

// ---- Timestamp ----

func TestConvertDeptrack_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
}

// ---- Result codeDesc includes recommendation ----

func TestConvertDeptrack_ResultCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3")
	require.NotEmpty(t, req.Results)

	assert.Contains(t, req.Results[0].CodeDesc, "Update to version 2.6.0 or later.")
}

// ---- Requirement raw code (Heimdall CODE tab) ----

// Dependency-Track carries no literal source snippet, so requirement.code holds
// the raw finding object serialized as indented JSON. Pin that it is set and
// round-trips byte-structurally back to the source finding (CODE-tab fidelity),
// including fields the typed struct drops (aliases, source, vulnId).
func TestConvertDeptrack_RequirementCode(t *testing.T) {
	for _, name := range []string{"input/fpf-default.json", "input/fpf-info-vulnerability.json"} {
		t.Run(name, func(t *testing.T) {
			input := loadFixture(t, name)
			result, err := ConvertDeptrackToHDF(input, testVersion)
			require.NoError(t, err)

			var raw struct {
				Findings []json.RawMessage `json:"findings"`
			}
			require.NoError(t, json.Unmarshal(input, &raw))

			reqs := result.Baselines[0].Requirements
			require.Len(t, reqs, len(raw.Findings))
			for i, req := range reqs {
				require.NotNil(t, req.Code, "req %d: Code is nil; Heimdall CODE tab would be empty", i)
				var got, want interface{}
				require.NoError(t, json.Unmarshal([]byte(*req.Code), &got), "req %d: Code is not valid JSON", i)
				require.NoError(t, json.Unmarshal(raw.Findings[i], &want))
				assert.Equal(t, want, got, "req %d: Code does not round-trip to source finding object", i)
			}
		})
	}
}

// TestConvertDeptrack_RequirementCode_Aliases pins that the untyped fields the
// Go struct drops (aliases, source, vulnId) survive into requirement.code.
func TestConvertDeptrack_RequirementCode_Aliases(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements,
		"ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3")
	require.NotNil(t, req.Code)
	assert.Contains(t, *req.Code, "CVE-2022-2053")
	assert.Contains(t, *req.Code, "GHSA-95rf-557x-44g5")
	assert.Contains(t, *req.Code, "\"vulnId\": \"48\"")
}

// buildFindingCode branch coverage: success, empty-raw (NOT-IN-SOURCE / zero
// value), and json.Indent error paths.
func TestBuildFindingCode_Branches(t *testing.T) {
	// success: raw reformatted with two-space indent
	f := DeptrackFinding{raw: json.RawMessage(`{"matrix":"x","analysis":{"isSuppressed":false}}`)}
	assert.Equal(t,
		"{\n  \"matrix\": \"x\",\n  \"analysis\": {\n    \"isSuppressed\": false\n  }\n}",
		buildFindingCode(f))

	// empty raw (zero-value finding, never unmarshaled) -> "{}"
	assert.Equal(t, "{}", buildFindingCode(DeptrackFinding{}))

	// invalid raw -> json.Indent errors -> "{}"
	assert.Equal(t, "{}", buildFindingCode(DeptrackFinding{raw: json.RawMessage(`{invalid`)}))
}

// DeptrackFinding.UnmarshalJSON error path.
func TestDeptrackFinding_UnmarshalJSON_Error(t *testing.T) {
	var f DeptrackFinding
	assert.Error(t, f.UnmarshalJSON([]byte(`{invalid`)))
}

// ---- Impact mapping table test ----

func TestGetImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"CRITICAL", 0.9},
		{"critical", 0.9},
		{"HIGH", 0.7},
		{"high", 0.7},
		{"MEDIUM", 0.5},
		{"medium", 0.5},
		{"LOW", 0.3},
		{"low", 0.3},
		{"INFO", 0.0},
		{"info", 0.0},
		{"UNASSIGNED", 0.5},
		{"unassigned", 0.5},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

func TestSnapshots(t *testing.T) {
	// fpf-no-vulnerabilities has zero findings, so its startTime is the synthesized
	// no-findings placeholder time (not input-derived); mask only that fixture. The
	// findings fixtures derive startTime from meta.timestamp and are asserted.
	shared.RunSnapshotTests(t, "deptrack-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertDeptrackToHDF(input, "1.0.0")
	}, "fpf-no-vulnerabilities.json")
}

// Ground-truth anchor: the converter emits one requirement per top-level
// findings[] entry. The source count is derived independently of the converter's
// parser (shared/go/anchor.go), so a silent under-extraction fails even when
// Go/TS golden parity agrees.
func TestConvertDeptrack_FindingsAnchor(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "findings"),
		"fpf-default.json: one requirement per findings[]")
}

func TestConvertDeptrack_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/fpf-default.json")
	result, err := ConvertDeptrackToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "every requirement must have verificationMethod set")
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q should be marked automated", req.ID)
	}
}
