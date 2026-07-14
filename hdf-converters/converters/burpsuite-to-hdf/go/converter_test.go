package burpsuite

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConverterVersion = "test-version"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	fixturePath := filepath.Join("..", "fixtures", name)
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("Failed to read fixture %s: %v", name, err)
	}
	return data
}

// --- Validation tests ---

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "burpsuite-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertBurpsuiteToHDF(input, testConverterVersion) },
		MinimalFixture: "zero.webappsecurity.com.xml",
		InvalidInput:   "<not valid xml",
	})
}

func TestConvertBurpsuiteToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
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

func TestConvertBurpsuiteToHDF_EmptyIssues(t *testing.T) {
	input := loadFixture(t, "input/empty.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "burpsuite-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Burp Suite")
	assert.Contains(t, req.Results[0].CodeDesc, "Unknown")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// --- Real fixture tests ---

func TestConvertBurpsuiteToHDF_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines, 1)
	// 60 issues in the fixture, grouped by type (14 unique types)
	assert.Len(t, result.Baselines[0].Requirements, 14)
}

func TestConvertBurpsuiteToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "burpsuite-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

func TestConvertBurpsuiteToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Equal(t, "BurpSuite", *result.Tool.Name)
	assert.Equal(t, "XML", *result.Tool.Format)
	assert.Equal(t, "2020.1", *result.Tool.Version)
}

func TestConvertBurpsuiteToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "BurpSuite Scan", result.Baselines[0].Name)
}

func TestConvertBurpsuiteToHDF_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "http://zero.webappsecurity.com")
}

func TestConvertBurpsuiteToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Len(t, result.Baselines[0].ResultsChecksum.Value, 64)
}

func TestConvertBurpsuiteToHDF_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2020, result.Timestamp.Year())
	assert.Equal(t, 27, result.Timestamp.Day())
}

// --- Target ---

func TestConvertBurpsuiteToHDF_Target(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, "http://zero.webappsecurity.com", result.Components[0].Name)
	assert.Equal(t, hdf.Application, result.Components[0].Type)
}

// --- Impact mapping ---

func TestConvertBurpsuiteToHDF_ImpactInformation(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Type 2098688 = "Cross-origin resource sharing" with severity "Information"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertBurpsuiteToHDF_ImpactMedium(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Type 16777472 = severity "Medium"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "16777472")
	assert.Equal(t, 0.5, req.Impact)
}

func TestConvertBurpsuiteToHDF_ImpactLow(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Type 16777984 = severity "Low"
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "16777984")
	assert.Equal(t, 0.3, req.Impact)
}

func Test_getImpact(t *testing.T) {
	assert.Equal(t, 0.7, getImpact("High"))
	assert.Equal(t, 0.7, getImpact("high"))
	assert.Equal(t, 0.5, getImpact("Medium"))
	assert.Equal(t, 0.5, getImpact("medium"))
	assert.Equal(t, 0.3, getImpact("Low"))
	assert.Equal(t, 0.3, getImpact("low"))
	assert.Equal(t, 0.3, getImpact("Information"))
	assert.Equal(t, 0.3, getImpact("information"))
	assert.Equal(t, 0.3, getImpact("unknown"))
}

// --- Grouping by type ---

func TestConvertBurpsuiteToHDF_GroupingByType(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Type 2098688 (Cross-origin resource sharing) appears many times in the fixture
	// Each appearance becomes a separate result within the same requirement
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	assert.Greater(t, len(req.Results), 1, "Multiple issues with same type should produce multiple results")
}

// --- Results ---

func TestConvertBurpsuiteToHDF_AllStatusFailed(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status)
		}
	}
}

func TestConvertBurpsuiteToHDF_CodeDescContainsHost(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	require.Greater(t, len(req.Results), 0)
	assert.Contains(t, req.Results[0].CodeDesc, "Host:")
	assert.Contains(t, req.Results[0].CodeDesc, "54.82.22.214")
	assert.Contains(t, req.Results[0].CodeDesc, "http://zero.webappsecurity.com")
}

func TestConvertBurpsuiteToHDF_CodeDescContainsLocation(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	require.Greater(t, len(req.Results), 0)
	assert.Contains(t, req.Results[0].CodeDesc, "Location:")
}

// --- NIST tags ---

func TestConvertBurpsuiteToHDF_NISTMappedCWE(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Type 2098688 has CWE-942 in vulnerabilityClassifications
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Greater(t, len(nistSlice), 0)
}

func TestConvertBurpsuiteToHDF_NISTFallback(t *testing.T) {
	// For issues without CWE mappings, should fall back to SA-11, RA-5
	input := []byte(`<?xml version="1.0"?><issues burpVersion="2020.1" exportTime="Thu Feb 27 09:28:17 EST 2020">
  <issue>
    <serialNumber>1</serialNumber>
    <type>999999</type>
    <name>Test Issue</name>
    <host ip="1.2.3.4">http://test.com</host>
    <path>/test</path>
    <location>/test</location>
    <severity>Low</severity>
    <confidence>Certain</confidence>
  </issue>
</issues>`)
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "999999")

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Len(t, nistSlice, 2)
	assert.Equal(t, "SA-11", nistSlice[0])
	assert.Equal(t, "RA-5", nistSlice[1])
}

// --- CCI tags ---

func TestConvertBurpsuiteToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")

	cciVal, ok := req.Tags["cci"]
	require.True(t, ok, "cci tag missing")
	cciSlice, ok := cciVal.([]interface{})
	require.True(t, ok, "cci tag not a slice")
	assert.Greater(t, len(cciSlice), 0)
}

// --- CWE tag ---

func TestConvertBurpsuiteToHDF_CWEIDTag(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")

	cweVal, ok := req.Tags["cweid"]
	require.True(t, ok, "cweid tag missing")
	assert.Contains(t, cweVal, "CWE-942")
}

// --- Descriptions ---

func TestConvertBurpsuiteToHDF_CheckDescription(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	require.Greater(t, len(req.Descriptions), 0)

	// Find check description (issueBackground)
	var checkDesc *hdf.Description
	for i := range req.Descriptions {
		if req.Descriptions[i].Label == "check" {
			checkDesc = &req.Descriptions[i]
			break
		}
	}
	require.NotNil(t, checkDesc, "check description missing")
	assert.Contains(t, checkDesc.Data, "cross-origin resource sharing")
	// HTML should be stripped
	assert.NotContains(t, checkDesc.Data, "<p>")
}

func TestConvertBurpsuiteToHDF_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")

	var fixDesc *hdf.Description
	for i := range req.Descriptions {
		if req.Descriptions[i].Label == "fix" {
			fixDesc = &req.Descriptions[i]
			break
		}
	}
	require.NotNil(t, fixDesc, "fix description missing")
	assert.Contains(t, fixDesc.Data, "CORS policy")
	// HTML should be stripped
	assert.NotContains(t, fixDesc.Data, "<p>")
}

func TestConvertBurpsuiteToHDF_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")

	var defaultDesc *hdf.Description
	for i := range req.Descriptions {
		if req.Descriptions[i].Label == "default" {
			defaultDesc = &req.Descriptions[i]
			break
		}
	}
	require.NotNil(t, defaultDesc, "default description missing")
}

// --- Title mapping ---

func TestConvertBurpsuiteToHDF_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Cross-origin resource sharing", *req.Title)
}

// --- CWE parsing from vulnerabilityClassifications HTML ---

func Test_parseCWEIDs(t *testing.T) {
	html := `<ul>
<li><a href="https://cwe.mitre.org/data/definitions/942.html">CWE-942: Overly Permissive Cross-domain Whitelist</a></li>
</ul>`
	cweIDs := parseCWEIDs(html)
	assert.Equal(t, []string{"CWE-942"}, cweIDs)
}

func Test_parseCWEIDs_Multiple(t *testing.T) {
	html := `<ul>
<li><a href="https://cwe.mitre.org/data/definitions/20.html">CWE-20: Improper Input Validation</a></li>
<li><a href="https://cwe.mitre.org/data/definitions/116.html">CWE-116: Improper Encoding or Escaping of Output</a></li>
</ul>`
	cweIDs := parseCWEIDs(html)
	assert.Equal(t, []string{"CWE-116", "CWE-20"}, cweIDs)
}

func Test_parseCWEIDs_Empty(t *testing.T) {
	cweIDs := parseCWEIDs("")
	assert.Empty(t, cweIDs)
}

func Test_parseCWEIDs_NoCWE(t *testing.T) {
	html := `<ul><li>No CWE here</li></ul>`
	cweIDs := parseCWEIDs(html)
	assert.Empty(t, cweIDs)
}

// --- Format code desc ---

func Test_formatCodeDesc(t *testing.T) {
	desc := formatCodeDesc("54.82.22.214", "http://test.com", "/test/path", "<b>detail</b>", "Certain")
	assert.Contains(t, desc, "Host: ip: 54.82.22.214, url: http://test.com")
	assert.Contains(t, desc, "Location: /test/path")
	assert.Contains(t, desc, "issueDetail: detail")
	assert.Contains(t, desc, "confidence: Certain")
}

func Test_formatCodeDesc_Empty(t *testing.T) {
	desc := formatCodeDesc("", "", "", "", "")
	assert.Contains(t, desc, "Host: ip: , url:")
}

// --- Confidence tag ---

func TestConvertBurpsuiteToHDF_ConfidenceTag(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2098688")
	assert.Equal(t, "Certain", req.Tags["confidence"])
}

func TestConvertBurpsuiteToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "burpsuite-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertBurpsuiteToHDF(input, "1.0.0")
	})
}

func TestConvertBurpsuiteToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
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

// --- Ground-truth anchor (see shared/go/anchor.go) ---
// burpsuite groups issues by <type> (one requirement per distinct issue type),
// so count distinct <type> values independently of the converter's parser.
func countDistinctBurpTypes(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Issues []struct {
			Type string `xml:"type"`
		} `xml:"issue"`
	}
	require.NoError(t, xml.Unmarshal(input, &doc))
	seen := map[string]struct{}{}
	for _, i := range doc.Issues {
		seen[i.Type] = struct{}{}
	}
	return len(seen)
}

func TestConvertBurpsuiteToHDF_DistinctTypeAnchor(t *testing.T) {
	input := loadFixture(t, "input/zero.webappsecurity.com.xml")
	result, err := ConvertBurpsuiteToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countDistinctBurpTypes(t, input),
		"zero.webappsecurity.com.xml: one requirement per distinct <issue> <type>")
}
