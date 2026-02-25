package zap_to_hdf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestConvertZapToHDF_InvalidJSON(t *testing.T) {
	_, err := ConvertZapToHDF([]byte("not valid json"), testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ZAP JSON")
}

func TestConvertZapToHDF_EmptyInput(t *testing.T) {
	_, err := ConvertZapToHDF([]byte(""), testConverterVersion)
	assert.Error(t, err)
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

func TestConvertZapToHDF_DataSource(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	assert.Equal(t, "OWASP ZAP", *result.DataSource.Name)
	assert.Equal(t, "JSON", *result.DataSource.Format)
	assert.Equal(t, "2.7.0", *result.DataSource.Version)
}

func TestConvertZapToHDF_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "example.com", result.Baselines[0].Name)
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

func TestRiskCodeToImpact(t *testing.T) {
	assert.Equal(t, 0.3, RiskCodeToImpact("0"))
	assert.Equal(t, 0.3, RiskCodeToImpact("1"))
	assert.Equal(t, 0.5, RiskCodeToImpact("2"))
	assert.Equal(t, 0.7, RiskCodeToImpact("3"))
	assert.Equal(t, 0.5, RiskCodeToImpact("99"))
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

// --- SARIF detection ---

func TestIsSarif(t *testing.T) {
	sarifInput := []byte(`{"$schema":"test","version":"2.1.0","runs":[{}]}`)
	assert.True(t, IsSarif(sarifInput))

	zapInput := []byte(`{"@version":"2.7.0","site":[]}`)
	assert.False(t, IsSarif(zapInput))

	invalidJSON := []byte(`not json`)
	assert.False(t, IsSarif(invalidJSON))
}

func TestConvertZapToHDF_SARIFInput(t *testing.T) {
	sarifInput := []byte(`{"$schema":"test","version":"2.1.0","runs":[{"tool":{"driver":{"name":"Test"}},"results":[]}]}`)
	_, err := ConvertZapToHDF(sarifInput, testConverterVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SARIF")
}

// --- Site selection ---

func TestSelectSite(t *testing.T) {
	sites := []ZapSite{
		{Host: "small", Alerts: []ZapAlert{{PluginID: "1"}}},
		{Host: "large", Alerts: []ZapAlert{{PluginID: "1"}, {PluginID: "2"}, {PluginID: "3"}}},
		{Host: "medium", Alerts: []ZapAlert{{PluginID: "1"}, {PluginID: "2"}}},
	}
	best := SelectSiteForTest(sites)
	require.NotNil(t, best)
	assert.Equal(t, "large", best.Host)
}

func TestSelectSite_Empty(t *testing.T) {
	best := SelectSiteForTest([]ZapSite{})
	assert.Nil(t, best)
}

// --- Deduplication ---

func TestDeduplicateID(t *testing.T) {
	assert.Equal(t, "10021", DeduplicateID("10021", 0))
	assert.Equal(t, "10021.1", DeduplicateID("10021", 1))
	assert.Equal(t, "10021.2", DeduplicateID("10021", 2))
}

// --- CWE parsing ---

func TestParseCweID(t *testing.T) {
	assert.Equal(t, 16, ParseCweID("16"))
	assert.Equal(t, 0, ParseCweID(""))
	assert.Equal(t, 0, ParseCweID("0"))
	assert.Equal(t, 0, ParseCweID("abc"))
}

// --- StripHTML ---

func TestStripHTML(t *testing.T) {
	assert.Equal(t, "Hello world", StripHTMLForTest("<p>Hello</p><p>world</p>"))
	assert.Equal(t, "plain text", StripHTMLForTest("plain text"))
	assert.Equal(t, "", StripHTMLForTest(""))
}

// --- Webgoat fixture ---

func TestConvertZapToHDF_Webgoat_SelectsSiteWithMostAlerts(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	assert.Equal(t, "mymac.com", result.Baselines[0].Name)
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

func TestConvertZapToHDF_Webgoat_DataSourceVersion(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.NotNil(t, result.DataSource)
	assert.Equal(t, "2.7.0", *result.DataSource.Version)
}
