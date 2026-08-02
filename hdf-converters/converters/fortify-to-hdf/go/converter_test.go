package fortify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	inputPath := filepath.Join(shared.GetConvertersDir(), "fortify-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(inputPath)
	require.NoError(t, err, "Failed to read fixture: %s", name)
	return data
}

func TestConvertFortifyToHDF_ControlType(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(inputData, converterVersion)
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

func TestConvertFortifyToHDF_Sample(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err, "Conversion should succeed")
	require.NotNil(t, result, "Result should not be nil")

	// Verify generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "fortify-to-hdf", result.Generator.Name)
	assert.Equal(t, converterVersion, result.Generator.Version)

	// Verify baselines — one baseline per FVDL file
	require.Len(t, result.Baselines, 1, "Should have 1 baseline")
	baseline := result.Baselines[0]
	assert.Equal(t, "Fortify Scan", baseline.Name)

	// Verify that requirements exist — one per unique Description classID
	// The fixture has 5 unique Description classIDs
	assert.Len(t, baseline.Requirements, 5, "Should have 5 requirements (one per Description classID)")

	// Verify targets
	require.Len(t, result.Components, 1, "Should have 1 target")
	assert.Equal(t, hdf.Repository, result.Components[0].Type)

	// Write output for differential testing
	shared.WriteOutput(t, "fortify-to-hdf", "fortify_webgoat_results.json", result)
}

func TestConvertFortifyToHDF_BaselineMetadata(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Title should contain "Fortify Static Analyzer Scan"
	require.NotNil(t, baseline.Title)
	assert.Contains(t, *baseline.Title, "Fortify Static Analyzer Scan")

	// Summary should contain UUID
	require.NotNil(t, baseline.Summary)
	assert.Contains(t, *baseline.Summary, "b5e71375-1a97-4708-a07e-9a7e5fedeafe")

	// Version should be engine version
	require.NotNil(t, baseline.Version)
	assert.Equal(t, "19.1.0.2241", *baseline.Version)

	// ResultsChecksum should be populated
	require.NotNil(t, baseline.ResultsChecksum)
	assert.Equal(t, hdf.Sha256, baseline.ResultsChecksum.Algorithm)
	assert.Len(t, baseline.ResultsChecksum.Value, 64, "SHA-256 hash should be 64 hex chars")
}

func TestConvertFortifyToHDF_Tool(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Fortify", *result.Tool.Name)
	require.NotNil(t, result.Tool.Format)
	assert.Equal(t, "FVDL", *result.Tool.Format)
}

func TestConvertFortifyToHDF_RequirementFields(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Find the "Path Manipulation" requirement (classID 823FE039-...)
	pathManip := shared.MustFindRequirement(t, baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")

	// ID is the classID
	assert.Equal(t, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59", pathManip.ID)

	// Title comes from Abstract (HTML stripped)
	require.NotNil(t, pathManip.Title)
	assert.NotEmpty(t, *pathManip.Title)
	assert.NotContains(t, *pathManip.Title, "<Content>")

	// Impact derived from DefaultSeverity / 5
	// DefaultSeverity=3.0 -> 3.0/5 = 0.6
	assert.Equal(t, 0.6, pathManip.Impact)

	// Should have descriptions with label "default" from Explanation
	require.Greater(t, len(pathManip.Descriptions), 0, "Should have descriptions")
	foundDefault := false
	for _, desc := range pathManip.Descriptions {
		if desc.Label == "default" {
			foundDefault = true
			assert.NotEmpty(t, desc.Data)
			assert.NotContains(t, desc.Data, "<Content>")
		}
	}
	assert.True(t, foundDefault, "Should have a default description")

	// Should have results — one per vulnerability with this classID
	assert.Greater(t, len(pathManip.Results), 0, "Should have results")
	for _, res := range pathManip.Results {
		assert.Equal(t, hdf.Failed, res.Status)
		assert.NotEmpty(t, res.CodeDesc)
	}
}

// requirement.code drives Heimdall's CODE tab. It must carry the raw Fortify
// source snippet (the FVDL <Snippet><Text>), not the codeDesc wrapper text.
func TestConvertFortifyToHDF_RequirementCode(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]
	pathManip := shared.MustFindRequirement(t, baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")

	require.NotNil(t, pathManip.Code, "requirement.code must carry the source snippet")
	code := *pathManip.Code

	// Raw source, not the "Path:/StartLine:/Code:" codeDesc wrapper.
	assert.False(t, strings.HasPrefix(code, "Path:"), "code should be raw source, not the codeDesc wrapper")
	assert.Contains(t, code, "System.out.println(MD5.getHashString(new File(element))")

	// The snippet appears verbatim inside the result codeDesc.
	require.NotEmpty(t, pathManip.Results)
	assert.Contains(t, pathManip.Results[0].CodeDesc, code)

	// Every requirement in this fixture has a primary-trace snippet.
	for _, req := range baseline.Requirements {
		assert.NotNil(t, req.Code, "requirement %q should have code populated", req.ID)
	}
}

// A finding whose primary trace carries no snippet must leave code unset
// (NOT-IN-SOURCE) rather than fabricating one.
func TestConvertFortifyToHDF_RequirementCode_NoSnippet(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C3</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I3</InstanceID></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C3">
  <Abstract>No trace</Abstract>
  <Explanation>Explanation text</Explanation>
</Description>
</FVDL>`)
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Code, "code must be unset when the finding carries no snippet")
}

// Node-bearing trace entries that carry no usable snippet (missing snippet
// attribute, or a snippet id absent from <Snippets>) must be skipped, leaving
// code unset rather than emitting an empty or fabricated value.
func TestConvertFortifyToHDF_RequirementCode_NodeWithoutSnippet(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>C9</ClassID></ClassInfo>
    <InstanceInfo><InstanceID>I9</InstanceID></InstanceInfo>
    <AnalysisInfo><Unified><Trace><Primary>
      <Entry><Node isDefault="true"><SourceLocation path="a.java" line="1"/></Node></Entry>
      <Entry><Node isDefault="false"><SourceLocation path="b.java" line="2" snippet="MISSING"/></Node></Entry>
    </Primary></Trace></Unified></AnalysisInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="C9"><Abstract>Crafted</Abstract><Explanation>Expl</Explanation></Description>
<Snippets/>
</FVDL>`)
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Code, "code must be unset when no trace node resolves to a snippet")
}

func TestConvertFortifyToHDF_NISTTags(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// The Path Manipulation description has a NIST reference "SI-10" in its References
	pathManip := shared.MustFindRequirement(t, baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")

	tags := pathManip.Tags
	require.NotNil(t, tags, "Tags should not be nil")
	nist, ok := tags["nist"]
	assert.True(t, ok, "Should have nist tag")
	nistSlice, ok := nist.([]interface{})
	assert.True(t, ok, "nist should be a slice")
	assert.Greater(t, len(nistSlice), 0, "Should have at least one NIST tag")
}

func TestConvertFortifyToHDF_SnippetInCodeDesc(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Check that at least one requirement has results with snippet-based code descriptions
	foundSnippet := false
	for _, req := range baseline.Requirements {
		for _, res := range req.Results {
			if res.CodeDesc != "" {
				foundSnippet = true
				break
			}
		}
		if foundSnippet {
			break
		}
	}
	assert.True(t, foundSnippet, "At least one result should have a code description")
}

func TestConvertFortifyToHDF_Timestamp(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2019, result.Timestamp.Year())
	assert.Equal(t, 10, int(result.Timestamp.Month()))
	assert.Equal(t, 2, result.Timestamp.Day())
}

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "fortify-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertFortifyToHDF(input, converterVersion) },
		MinimalFixture: "fortify_webgoat_results.fvdl",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertFortifyToHDF_MinimalFVDL(t *testing.T) {
	minimalFVDL := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<CreatedTS date="2024-01-15" time="10:00:00"/>
<UUID>test-uuid-1234</UUID>
<Build>
  <BuildID>test</BuildID>
  <NumberFiles>0</NumberFiles>
  <SourceBasePath>/tmp/test</SourceBasePath>
  <SourceFiles/>
</Build>
<Vulnerabilities/>
<Description contentType="preformatted" classID="TEST-001">
  <Abstract>Test abstract</Abstract>
  <Explanation>Test explanation</Explanation>
  <Recommendations>Test recommendations</Recommendations>
  <References/>
</Description>
<Snippets/>
<EngineData>
  <EngineVersion>20.0.0</EngineVersion>
  <RulePacks/>
  <Properties type="System"/>
  <CommandLine/>
  <Errors/>
  <MachineInfo/>
</EngineData>
</FVDL>`)

	result, err := ConvertFortifyToHDF(minimalFVDL, converterVersion)
	require.NoError(t, err, "Minimal FVDL should convert successfully")
	require.NotNil(t, result)

	assert.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]
	assert.Equal(t, "Fortify Scan", baseline.Name)
	// With 1 description but 0 vulnerabilities matching, should have 1 requirement with 0 results
	assert.Len(t, baseline.Requirements, 1)
}

func TestConvertFortifyToHDF_EmptyFindings(t *testing.T) {
	inputData := loadFixture(t, "empty.fvdl")

	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	baseline := result.Baselines[0]

	require.Len(t, baseline.Requirements, 1, "empty input must synthesize one placeholder requirement")
	req := baseline.Requirements[0]
	assert.Equal(t, "fortify-no-findings", req.ID)

	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Fortify")
	assert.Contains(t, req.Results[0].CodeDesc, "/src/cleanproject")
}

func TestConvertFortifyToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertFortifyToHDF(input, converterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "fortify-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertFortifyToHDF(input, "1.0.0")
	})
}

// Ground-truth anchor: the converter emits one requirement per FVDL
// <Description> element (each carrying a classID; vulnerabilities are grouped
// into these). The <Description> count is derived from the raw XML independently
// of the converter's parser (shared/go/anchor.go), so a silent under-extraction
// fails even when Go/TS golden parity agrees.
func TestConvertFortifyToHDF_DescriptionAnchor(t *testing.T) {
	input := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountXMLElements(t, input, "Description"),
		"fortify_webgoat_results.fvdl: one requirement per FVDL <Description>")
}

// CWE identifiers carried by the FVDL "Standards Mapping - Common Weakness
// Enumeration" reference must surface as first-class requirement.cwe[] entries
// ("CWE-NN"), and their CWE->NIST mapping must merge into tags.nist.
func TestConvertFortifyToHDF_CWE(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(inputData, converterVersion)
	require.NoError(t, err)

	baseline := result.Baselines[0]

	// Path Manipulation: "CWE ID 22, CWE ID 73" -> ["CWE-22","CWE-73"].
	pathManip := shared.MustFindRequirement(t, baseline.Requirements, "823FE039-A7FE-4AAD-B976-9EC53FFE4A59")
	assert.Equal(t, []string{"CWE-22", "CWE-73"}, pathManip.Cwe)

	// CWE-497 maps to NIST SI-11; the native reference is AC-4, so the merged
	// tags.nist must carry BOTH controls.
	sysInfo := shared.MustFindRequirement(t, baseline.Requirements, "FE4EADF2-7055-4C36-863E-5A01C4A0E1A4")
	assert.Equal(t, []string{"CWE-497"}, sysInfo.Cwe)
	nist := toStringSlice(t, sysInfo.Tags["nist"])
	assert.Contains(t, nist, "AC-4", "native NIST control must be preserved")
	assert.Contains(t, nist, "SI-11", "CWE->NIST mapping must be merged in")

	// A CWE whose ID has no NIST mapping (CWE-561) still yields cwe[] but leaves
	// the native NIST untouched.
	deadCode := shared.MustFindRequirement(t, baseline.Requirements, "3E7BCE41-4A79-49FF-8B8B-3F55F1F2DC5E")
	assert.Equal(t, []string{"CWE-561"}, deadCode.Cwe)
	assert.Equal(t, []string{"SA-11", "RA-5"}, toStringSlice(t, deadCode.Tags["nist"]))
}

func toStringSlice(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, ok := v.([]string)
	if ok {
		return raw
	}
	ifaces, ok := v.([]interface{})
	require.True(t, ok, "expected slice, got %T", v)
	out := make([]string, len(ifaces))
	for i, e := range ifaces {
		out[i] = e.(string)
	}
	return out
}

// A finding whose Description carries no CWE reference must leave cwe unset.
func TestConvertFortifyToHDF_CWE_Absent(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CN</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CN">
  <Abstract>No CWE</Abstract><Explanation>e</Explanation>
  <References>
    <Reference><Title>SI-10</Title><Author>Standards Mapping - NIST Special Publication 800-53 Revision 4</Author></Reference>
  </References>
</Description>
</FVDL>`)
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Cwe, "cwe must be unset when no CWE reference is present")
	assert.Equal(t, []string{"SI-10"}, toStringSlice(t, req.Tags["nist"]))
}

// A CWE-authored reference whose title carries no numeric ID yields no cwe[].
func TestConvertFortifyToHDF_CWE_NoNumericID(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CX</ClassID><DefaultSeverity>3.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>3.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CX">
  <Abstract>a</Abstract><Explanation>e</Explanation>
  <References>
    <Reference><Title>Not applicable</Title><Author>Standards Mapping - Common Weakness Enumeration</Author></Reference>
  </References>
</Description>
</FVDL>`)
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Nil(t, req.Cwe, "cwe must be unset when the CWE reference carries no numeric ID")
}

// Impact is derived from the per-instance InstanceSeverity, NOT the class-level
// DefaultSeverity. When they diverge, the instance value wins.
func TestConvertFortifyToHDF_InstanceSeverityImpact(t *testing.T) {
	input := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<FVDL xmlns="xmlns://www.fortifysoftware.com/schema/fvdl" version="1.12">
<Vulnerabilities>
  <Vulnerability>
    <ClassInfo><ClassID>CDIV</ClassID><DefaultSeverity>5.0</DefaultSeverity></ClassInfo>
    <InstanceInfo><InstanceID>I</InstanceID><InstanceSeverity>1.0</InstanceSeverity></InstanceInfo>
  </Vulnerability>
</Vulnerabilities>
<Description classID="CDIV"><Abstract>Divergent</Abstract><Explanation>e</Explanation></Description>
</FVDL>`)
	result, err := ConvertFortifyToHDF(input, converterVersion)
	require.NoError(t, err)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, 0.2, req.Impact, "impact must use InstanceSeverity (1.0/5), not DefaultSeverity (5.0/5)")
}

func TestConvertFortifyToHDF_VerificationMethod(t *testing.T) {
	inputData := loadFixture(t, "fortify_webgoat_results.fvdl")
	result, err := ConvertFortifyToHDF(inputData, converterVersion)
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
