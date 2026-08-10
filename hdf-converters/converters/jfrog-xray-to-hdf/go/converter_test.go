package jfrogxray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		ConverterName:  "jfrog-xray-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertJfrogXrayToHDF(input, testVersion) },
		MinimalFixture: "jfrog_xray_sample.json",
	})
}

// ---- Baseline structure ----

func TestConvertJfrogXray_BaselineCount(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
}

func TestConvertJfrogXray_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	assert.Equal(t, "JFrog Xray Scan", result.Baselines[0].Name)
}

func TestConvertJfrogXray_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// 30 entries with 17 unique summaries → 17 unique requirements
	assert.Len(t, result.Baselines[0].Requirements, 17)
}

func TestConvertJfrogXray_Checksum(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertJfrogXray_Generator(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "jfrog-xray-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertJfrogXray_Tool(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "JFrog Xray", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Target ----

func TestConvertJfrogXray_Target(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, "JFrog Xray Scan", result.Components[0].Name)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// ---- Severity → Impact mapping ----

func TestConvertJfrogXray_SeverityImpact(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// All requirements should have valid impact values
	for _, req := range reqs {
		assert.GreaterOrEqual(t, req.Impact, 0.0)
		assert.LessOrEqual(t, req.Impact, 1.0)
	}

	// Check specific severity levels exist by looking for known impacts
	hasHigh := false
	hasMedium := false
	hasLow := false
	for _, req := range reqs {
		if req.Impact == 0.7 {
			hasHigh = true
		}
		if req.Impact == 0.5 {
			hasMedium = true
		}
		if req.Impact == 0.3 {
			hasLow = true
		}
	}
	assert.True(t, hasHigh, "expected High severity (0.7) requirements")
	assert.True(t, hasMedium, "expected Medium severity (0.5) requirements")
	assert.True(t, hasLow, "expected Low severity (0.3) requirements")
}

// ---- ID generation: empty ID → hash of summary ----

func TestConvertJfrogXray_EmptyIDGeneratesHash(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		assert.NotEmpty(t, req.ID, "all requirements should have a non-empty ID")
	}
}

// ---- Deduplication: duplicate summaries → grouped results ----

func TestConvertJfrogXray_Dedup(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// Total results across all requirements should equal total data entries (27)
	totalResults := 0
	for _, req := range reqs {
		totalResults += len(req.Results)
	}
	assert.Equal(t, 27, totalResults, "total results should match total data entries")

	// Some requirements should have more than 1 result (duplicate summaries)
	hasMultipleResults := false
	for _, req := range reqs {
		if len(req.Results) > 1 {
			hasMultipleResults = true
			break
		}
	}
	assert.True(t, hasMultipleResults, "expected deduplication to group entries by ID/summary")
}

// ---- All results are Failed ----

func TestConvertJfrogXray_AllResultsFailed(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, r := range req.Results {
			assert.Equal(t, hdf.Failed, r.Status,
				"all JFrog Xray vulnerabilities should be Failed (vuln %s)", req.ID)
		}
	}
}

// ---- Description ----

func TestConvertJfrogXray_Description(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Every requirement should have at least a default description
	for _, req := range reqs {
		desc := findDescription(req.Descriptions, "default")
		require.NotNil(t, desc, "expected a 'default' description for requirement %s", req.ID)
		assert.NotEmpty(t, desc.Data)
	}
}

// ---- CodeDesc includes source_comp_id and version info ----

func TestConvertJfrogXray_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// Every result should have a non-empty code_desc
	for _, req := range reqs {
		for _, r := range req.Results {
			assert.NotEmpty(t, r.CodeDesc, "code_desc should not be empty for requirement %s", req.ID)
		}
	}
}

// ---- CWE → NIST mapping ----

func TestConvertJfrogXray_CweToNist(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// All requirements should have nist tags (either mapped or fallback)
	for _, req := range reqs {
		nist := hdfutil.SafeStringSlice(req.Tags["nist"])
		require.NotNil(t, nist, "nist tag should be present for requirement %s", req.ID)
		assert.NotEmpty(t, nist, "nist tag should not be empty for requirement %s", req.ID)
	}
}

// ---- CWE is first-class (requirement.cwe[]), cweid tag removed ----

func TestConvertJfrogXray_CweFirstClass(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// The interim cweid tag must be gone everywhere — CWE now lives in cwe[].
	for _, req := range reqs {
		_, has := req.Tags["cweid"]
		assert.False(t, has, "cweid tag must be removed (now in requirement.cwe[]) for %s", req.ID)
	}

	// At least one requirement carries a first-class cwe[] (fixture has CWE-74,
	// CWE-835, CWE-668, etc.).
	hasCWE := false
	for _, req := range reqs {
		if len(req.Cwe) > 0 {
			hasCWE = true
			break
		}
	}
	assert.True(t, hasCWE, "expected at least one requirement with a cwe[]")
}

// ---- Structured CVSS / CWE / CVE scoring ----

func TestConvertJfrogXray_CvssV2AndV3Structured(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// handlebars CVE-2019-19919 carries both a v3 and a v2 score.
	req := findRequirementByTitle(result.Baselines[0].Requirements,
		"prior to 4.3.0 are vulnerable to Prototype Pollution")
	require.NotNil(t, req)
	require.Len(t, req.Cvss, 2, "expected one v3 then one v2 cvss entry")

	v3 := req.Cvss[0]
	assert.Equal(t, hdf.The31, v3.Version)
	require.NotNil(t, v3.BaseScore)
	assert.InDelta(t, 9.8, *v3.BaseScore, 0.001)
	require.NotNil(t, v3.BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", *v3.BaseVector)
	require.NotNil(t, v3.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityCritical, *v3.BaseSeverity)
	require.NotNil(t, v3.Source)
	assert.Equal(t, "CVE-2019-19919", *v3.Source)

	v2 := req.Cvss[1]
	assert.Equal(t, hdf.The20, v2.Version)
	require.NotNil(t, v2.BaseScore)
	assert.InDelta(t, 7.5, *v2.BaseScore, 0.001)
	require.NotNil(t, v2.BaseVector)
	assert.Equal(t, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", *v2.BaseVector)
	require.NotNil(t, v2.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityHigh, *v2.BaseSeverity)

	// CWE first-class + CVE in tags.cve (id is a summary hash, not the CVE).
	assert.Equal(t, []string{"CWE-74"}, req.Cwe)
	assert.Equal(t, []string{"CVE-2019-19919"}, hdfutil.SafeStringSlice(req.Tags["cve"]))
	assert.NotEmpty(t, hdfutil.SafeStringSlice(req.Tags["nist"]))
}

func TestConvertJfrogXray_CvssVersionFromFieldNotVector(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// acorn: v3 vector carries a CVSS:3.0/ prefix; v2 vector carries NO prefix,
	// so the version must come from the field name (2.0), not the vector. No CVE
	// and no CWE on this finding.
	acorn := findRequirementByTitle(result.Baselines[0].Requirements, "Acorn regexp.js")
	require.NotNil(t, acorn)
	require.Len(t, acorn.Cvss, 2)

	assert.Equal(t, hdf.The30, acorn.Cvss[0].Version)
	require.NotNil(t, acorn.Cvss[0].BaseVector)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", *acorn.Cvss[0].BaseVector)

	assert.Equal(t, hdf.The20, acorn.Cvss[1].Version)
	require.NotNil(t, acorn.Cvss[1].BaseVector)
	assert.Equal(t, "AV:N/AC:M/Au:N/C:N/I:N/A:C", *acorn.Cvss[1].BaseVector)

	// No CVE → no source and no tags.cve; no CWE → no cwe[].
	assert.Nil(t, acorn.Cvss[0].Source)
	assert.Empty(t, acorn.Cwe)
	_, hasCVE := acorn.Tags["cve"]
	assert.False(t, hasCVE)
}

func TestConvertJfrogXray_CvssV2Only(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// node-handlebars RCE carries only a v2 score (cvss_v3 absent → skipped).
	req := findRequirementByTitle(result.Baselines[0].Requirements, "node-handlebars Template Handling")
	require.NotNil(t, req)
	require.Len(t, req.Cvss, 1)
	assert.Equal(t, hdf.The20, req.Cvss[0].Version)
	require.NotNil(t, req.Cvss[0].BaseScore)
	assert.InDelta(t, 10.0, *req.Cvss[0].BaseScore, 0.001)
	require.NotNil(t, req.Cvss[0].BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityCritical, *req.Cvss[0].BaseSeverity)
}

func TestConvertJfrogXray_NoCvssWhenNoCves(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	// The lodash baseZipObject finding has more_details with no cves at all.
	req := findRequirementByTitle(result.Baselines[0].Requirements, "baseZipObject")
	require.NotNil(t, req)
	assert.Empty(t, req.Cvss)
	assert.Empty(t, req.Cwe)
	_, hasCVE := req.Tags["cve"]
	assert.False(t, hasCVE)
}

func TestParseCvssField(t *testing.T) {
	// score + prefixed vector
	s, v := parseCvssField("7.5/CVSS:3.0/AV:N/AC:L")
	require.NotNil(t, s)
	assert.InDelta(t, 7.5, *s, 0.001)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L", v)

	// score + bare (prefix-less) vector
	s, v = parseCvssField("7.1/AV:N/AC:M")
	require.NotNil(t, s)
	assert.InDelta(t, 7.1, *s, 0.001)
	assert.Equal(t, "AV:N/AC:M", v)

	// score only, no "/" → no vector
	s, v = parseCvssField("9.0")
	require.NotNil(t, s)
	assert.InDelta(t, 9.0, *s, 0.001)
	assert.Equal(t, "", v)

	// unparseable score, no "/" → nothing usable
	s, v = parseCvssField("garbage")
	assert.Nil(t, s)
	assert.Equal(t, "", v)

	// unparseable score with a trailing vector → score dropped, vector kept
	s, v = parseCvssField("bad/AV:N/AC:L")
	assert.Nil(t, s)
	assert.Equal(t, "AV:N/AC:L", v)

	// truly empty
	s, v = parseCvssField("")
	assert.Nil(t, s)
	assert.Equal(t, "", v)
}

// Synthetic input (test-only, not a committed fixture): a CVE with only a
// vector-bearing cvss_v3 whose score is unparseable, and no cvss_v2. Exercises
// the "emit vector, no score" v3 branch and the "cvss_v2 absent → skip" branch.
func TestConvertJfrogXray_CvssVectorOnlyAndV2Absent(t *testing.T) {
	synthetic := `{"data":[{"id":"x","severity":"High","summary":"synthetic vector-only",` +
		`"component_versions":{"more_details":{"cves":[{"cve":"CVE-9999-0001",` +
		`"cvss_v3":"bad/CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}}}]}`
	result, err := ConvertJfrogXrayToHDF([]byte(synthetic), testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Cvss, 1, "only the v3 metric should be emitted")
	assert.Equal(t, hdf.The31, req.Cvss[0].Version)
	assert.Nil(t, req.Cvss[0].BaseScore, "unparseable score must be omitted")
	require.NotNil(t, req.Cvss[0].BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", *req.Cvss[0].BaseVector)
	assert.Equal(t, []string{"CVE-9999-0001"}, hdfutil.SafeStringSlice(req.Tags["cve"]))
}

// ---- Title from summary ----

func TestConvertJfrogXray_Title(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	for _, req := range reqs {
		require.NotNil(t, req.Title, "title should not be nil for requirement %s", req.ID)
		assert.NotEmpty(t, *req.Title, "title should not be empty for requirement %s", req.ID)
	}
}

// ---- Empty data array ----

func TestConvertJfrogXray_EmptyDataSynthesizesPlaceholder(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)

	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 1, "empty-findings input must synthesize a single placeholder requirement")

	req := reqs[0]
	assert.Equal(t, "jfrog-xray-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "JFrog Xray")
	assert.Contains(t, codeDesc, "zero vulnerable components")
}

// ---- Severity helper ----

func TestGetImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"High", 0.7},
		{"high", 0.7},
		{"Medium", 0.5},
		{"medium", 0.5},
		{"Low", 0.3},
		{"low", 0.3},
		{"", 0.5},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.InDelta(t, tc.expected, getImpact(tc.severity), 0.001)
		})
	}
}

// ---- CODE tab: requirement.code carries the serialized entry ----

func findRequirementByTitle(reqs []hdf.EvaluatedRequirement, substr string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].Title != nil && strings.Contains(*reqs[i].Title, substr) {
			return &reqs[i]
		}
	}
	return nil
}

func TestConvertJfrogXray_CodeContainsEntryJSON(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)

	acorn := findRequirementByTitle(result.Baselines[0].Requirements, "Acorn regexp.js")
	require.NotNil(t, acorn, "expected the acorn requirement")
	require.NotNil(t, acorn.Code, "requirement.code must be populated for the Heimdall CODE tab")

	// Indented (2-space) serialization of the source entry object.
	assert.True(t, strings.HasPrefix(*acorn.Code, "{\n  \""), "code must be indented JSON")

	// The serialized code must round-trip to the source entry.
	var decoded XrayEntry
	require.NoError(t, json.Unmarshal([]byte(*acorn.Code), &decoded))
	assert.Equal(t, "npm://acorn:5.7.3", decoded.SourceCompID)
	assert.Equal(t, "High", decoded.Severity)
	assert.Equal(t, []string{"5.7.4", "6.4.1", "7.1.1"}, decoded.ComponentVersions.FixedVersions)
	require.Len(t, decoded.ComponentVersions.MoreDetails.CVEs, 1)
	assert.Equal(t,
		"7.5/CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
		decoded.ComponentVersions.MoreDetails.CVEs[0].CvssV3)
}

func TestSnapshots(t *testing.T) {
	// JFrog Xray export carries no scan time.
	shared.RunSnapshotTests(t, "jfrog-xray-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertJfrogXrayToHDF(input, "1.0.0")
	}, "*")
}

func TestConvertJfrogXrayToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
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

func TestConvertJfrogXray_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: JFrog Xray is an automated vulnerability scanner", req.ID)
	}
}

// countDistinctEntryIDs derives the ground-truth requirement count directly from
// the raw JSON, independent of the converter's structs: JFrog Xray groups
// data[] entries by their effective ID (the entry's id, or its summary when id
// is empty) and emits one requirement per group. A plain data[] count would
// over-count merged duplicates, so the grouping is re-derived here rather than
// reusing the converter's traversal.
func countDistinctEntryIDs(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Data []struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "anchor: invalid jfrog-xray JSON")
	seen := map[string]bool{}
	for _, e := range doc.Data {
		key := e.ID
		if key == "" {
			key = "summary:" + e.Summary
		}
		seen[key] = true
	}
	return len(seen)
}

// Ground-truth anchor: one requirement per distinct effective entry ID. Catches
// a silent under-extraction that TS/Go golden parity cannot see.
func TestConvertJfrogXray_EntryAnchor(t *testing.T) {
	input := loadFixture(t, "input/jfrog_xray_sample.json")
	result, err := ConvertJfrogXrayToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctEntryIDs(t, input),
		"jfrog_xray_sample.json: one requirement per distinct data[] entry ID")
}
