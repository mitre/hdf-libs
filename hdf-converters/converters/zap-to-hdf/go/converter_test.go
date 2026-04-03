package zap_to_hdf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
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

func findRequirement(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

// --- Validation tests ---

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "zap-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertZapToHDF(input, testConverterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertZapToHDF_MissingSiteArray(t *testing.T) {
	input := []byte(`{"@version": "2.7.0"}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

func TestConvertZapToHDF_EmptySiteArray(t *testing.T) {
	input := []byte(`{"@version": "2.7.0", "site": []}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 0)
}

// --- Minimal fixture tests ---
// minimal.json: Hand-crafted fixture matching ZAP JSON report format.
// Covers 2 alerts (pluginids 10021, 90022), 3 instances, CWE-16 + empty CWE,
// risk codes 1 and 2, HTML in descriptions, and attack field.

func TestConvertZapToHDF_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 2)
}

func TestConvertZapToHDF_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "zap-to-hdf", result.Generator.Name)
	assert.Equal(t, testConverterVersion, result.Generator.Version)
}

func TestConvertZapToHDF_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Equal(t, "OWASP ZAP", *result.Tool.Name)
	assert.Equal(t, "JSON", *result.Tool.Format)
	assert.Equal(t, "2.7.0", *result.Tool.Version)
}

func TestConvertZapToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "OWASP ZAP Scan", result.Baselines[0].Name)
}

func TestConvertZapToHDF_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "OWASP ZAP Scan of https://example.com", *result.Baselines[0].Title)
}

func TestConvertZapToHDF_BaselineSummary(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Equal(t, "ZAP Version 2.7.0", *result.Baselines[0].Summary)
}

func TestConvertZapToHDF_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Len(t, result.Baselines[0].ResultsChecksum.Value, 64)
}

func TestConvertZapToHDF_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2018, result.Timestamp.Year())
	assert.Equal(t, time.December, result.Timestamp.Month())
	assert.Equal(t, 6, result.Timestamp.Day())
}

// --- Targets ---

func TestConvertZapToHDF_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	assert.Equal(t, "example.com", result.Components[0].Name)
	assert.Equal(t, hdf.CopyrightApplication, result.Components[0].Type)
	require.NotNil(t, result.Components[0].URL)
	assert.Equal(t, "https://example.com", *result.Components[0].URL)
}

func TestConvertZapToHDF_NoTargetForUnknownHost(t *testing.T) {
	input := []byte(`{"@version": "2.7.0", "site": [{"alerts": []}]}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Empty(t, result.Components)
}

// --- Impact mapping ---

func TestConvertZapToHDF_ImpactRiskCode1(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertZapToHDF_ImpactRiskCode2(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req)
	assert.Equal(t, 0.5, req.Impact)
}

func Test_riskCodeToImpact(t *testing.T) {
	assert.Equal(t, 0.3, riskCodeToImpact("0"))
	assert.Equal(t, 0.3, riskCodeToImpact("1"))
	assert.Equal(t, 0.5, riskCodeToImpact("2"))
	assert.Equal(t, 0.7, riskCodeToImpact("3"))
	assert.Equal(t, 0.5, riskCodeToImpact("99"))
}

// --- Results from instances ---

func TestConvertZapToHDF_ResultCount(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req1 := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req1)
	assert.Len(t, req1.Results, 1)

	req2 := findRequirement(result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req2)
	assert.Len(t, req2.Results, 2)
}

func TestConvertZapToHDF_AllStatusFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status)
		}
	}
}

func TestConvertZapToHDF_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, "URI: https://example.com/login | Method: GET | Param: X-Content-Type-Options", req.Results[0].CodeDesc)
}

func TestConvertZapToHDF_AttackMessage(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req)
	require.NotNil(t, req.Results[1].Message)
	assert.Equal(t, "' OR 1=1 --", *req.Results[1].Message)
}

// --- NIST mapping ---

func TestConvertZapToHDF_NISTMappedCWE(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Greater(t, len(nistSlice), 0)
}

func TestConvertZapToHDF_NISTFallbackEmptyCWE(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req)

	nistVal, ok := req.Tags["nist"]
	require.True(t, ok, "nist tag missing")
	nistSlice, ok := nistVal.([]interface{})
	require.True(t, ok, "nist tag not a slice")
	assert.Len(t, nistSlice, 2)
	assert.Equal(t, "SA-11", nistSlice[0])
	assert.Equal(t, "RA-5", nistSlice[1])
}

// --- CCI tags ---

func TestConvertZapToHDF_CCITags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)

	cciVal, ok := req.Tags["cci"]
	require.True(t, ok, "cci tag missing")
	cciSlice, ok := cciVal.([]interface{})
	require.True(t, ok, "cci tag not a slice")
	assert.Greater(t, len(cciSlice), 0)
}

// --- Extra tags ---

func TestConvertZapToHDF_CWEIDTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, "16", req.Tags["cweid"])
}

func TestConvertZapToHDF_WASCIDTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, "15", req.Tags["wascid"])
}

func TestConvertZapToHDF_RiskDescTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, "Low (Medium)", req.Tags["riskdesc"])
}

func TestConvertZapToHDF_ConfidenceTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	assert.Equal(t, "2", req.Tags["confidence"])
}

// --- Descriptions ---

func TestConvertZapToHDF_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	require.Len(t, req.Descriptions, 2)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.NotContains(t, req.Descriptions[0].Data, "<p>")
	assert.Contains(t, req.Descriptions[0].Data, "X-Content-Type-Options was not set to 'nosniff'")
}

func TestConvertZapToHDF_CheckDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req)
	require.Len(t, req.Descriptions, 2)
	assert.Equal(t, "check", req.Descriptions[1].Label)
	assert.Contains(t, req.Descriptions[1].Data, "Content-Type header")
	assert.Contains(t, req.Descriptions[1].Data, "error type pages")
}

// --- SARIF routing ---

func TestConvertZapToHDF_SARIFInput(t *testing.T) {
	// SARIF input should be transparently delegated to the SARIF converter
	sarifInput := []byte(`{"$schema":"test","version":"2.1.0","runs":[{"tool":{"driver":{"name":"Test","version":"1.0"}},"results":[]}]}`)
	result, err := ConvertZapToHDF(sarifInput, testConverterVersion)
	require.NoError(t, err)
	assert.NotEqual(t, "OWASP ZAP Scan", result.Baselines[0].Name)
}

// --- Site selection ---

func TestSelectSite(t *testing.T) {
	sites := []ZapSite{
		{Host: "small", Alerts: []ZapAlert{{PluginID: "1"}}},
		{Host: "large", Alerts: []ZapAlert{{PluginID: "1"}, {PluginID: "2"}, {PluginID: "3"}}},
		{Host: "medium", Alerts: []ZapAlert{{PluginID: "1"}, {PluginID: "2"}}},
	}
	best := selectSite(sites)
	require.NotNil(t, best)
	assert.Equal(t, "large", best.Host)
}

func Test_selectSite_Empty(t *testing.T) {
	best := selectSite([]ZapSite{})
	assert.Nil(t, best)
}

// --- Deduplication ---

func Test_deduplicateID(t *testing.T) {
	assert.Equal(t, "10021", deduplicateID("10021", 0))
	assert.Equal(t, "10021.1", deduplicateID("10021", 1))
	assert.Equal(t, "10021.2", deduplicateID("10021", 2))
}

// --- CWE parsing ---

func Test_parseCweID(t *testing.T) {
	assert.Equal(t, 16, parseCweID("16"))
	assert.Equal(t, 0, parseCweID(""))
	assert.Equal(t, 0, parseCweID("0"))
	assert.Equal(t, 0, parseCweID("abc"))
}

// --- StripHTML ---

func Test_stripHTML(t *testing.T) {
	assert.Equal(t, "Hello world", shared.StripHTML("<p>Hello</p><p>world</p>"))
	assert.Equal(t, "plain text", shared.StripHTML("plain text"))
	assert.Equal(t, "", shared.StripHTML(""))
}

// --- Webgoat fixture ---
// webgoat.json: ZAP scan results from the OWASP WebGoat deliberately vulnerable application.
// Contains 2 sites, 25 alerts in the primary site (mymac.com), 15 unique plugin IDs.

func TestConvertZapToHDF_Webgoat_SelectsSiteWithMostAlerts(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Baseline.Name is the fixed scan label; the host goes into Targets
	assert.Equal(t, "OWASP ZAP Scan", result.Baselines[0].Name)
	require.Len(t, result.Components, 1)
	assert.Equal(t, "mymac.com", result.Components[0].Name)
}

func TestConvertZapToHDF_Webgoat_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// 25 alerts total, each gets its own requirement (duplicates get .1, .2, etc.)
	assert.Len(t, result.Baselines[0].Requirements, 25)
}

func TestConvertZapToHDF_Webgoat_Deduplication(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	ids := make([]string, len(result.Baselines[0].Requirements))
	for i, req := range result.Baselines[0].Requirements {
		ids[i] = req.ID
	}

	// 90028 appears many times
	assert.Contains(t, ids, "90028")
	assert.Contains(t, ids, "90028.1")
	assert.Contains(t, ids, "90028.2")
}

func TestConvertZapToHDF_Webgoat_ImpactRisk0(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "90028")
	require.NotNil(t, req)
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertZapToHDF_Webgoat_ImpactRisk3(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := findRequirement(result.Baselines[0].Requirements, "42")
	require.NotNil(t, req)
	assert.Equal(t, 0.7, req.Impact)
}

func TestConvertZapToHDF_Webgoat_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, 2018, result.Timestamp.Year())
	assert.Equal(t, time.December, result.Timestamp.Month())
	assert.Equal(t, 6, result.Timestamp.Day())
}

func TestConvertZapToHDF_Webgoat_ToolVersion(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	assert.Equal(t, "2.7.0", *result.Tool.Version)
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "zap-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertZapToHDF(input, "0.1.0")
	})
}
