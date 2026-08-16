package dbprotect

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test-0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join(shared.GetConvertersDir(), "dbprotect-to-hdf", "fixtures", name)
	data, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read fixture %s", name)
	return data
}

// ---- Input validation ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "dbprotect-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertDbprotectToHDF(input, testVersion) },
		MinimalFixture: "sample-check-results.xml",
		InvalidInput:   "<not valid xml",
	})
}

// ---- Check Results Details fixture ----

func TestConvertDbprotect_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
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
	assert.False(t, sawDerivation, "converter uses static-fallback NIST only; controlType must be omitted per helper gate")
}

func TestConvertDbprotect_CheckResults_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have generator
	require.NotNil(t, result.Generator)
	assert.Equal(t, "dbprotect-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)

	// Should have one baseline
	require.Len(t, result.Baselines, 1)

	// Should have tool
	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "DBProtect", *result.Tool.Name)
}

func TestConvertDbprotect_CheckResults_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "DBProtect Scan", result.Baselines[0].Name)
}

func TestConvertDbprotect_CheckResults_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Title comes from first row's "Job Name"
	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "Heimdal Test scan report generation")
}

func TestConvertDbprotect_CheckResults_BaselineSummary(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Contains(t, *result.Baselines[0].Summary, "Organization")
	assert.Contains(t, *result.Baselines[0].Summary, "CONDS181")
}

func TestConvertDbprotect_CheckResults_Checksum(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.Regexp(t, `^[a-f0-9]{64}$`, result.Baselines[0].ResultsChecksum.Value)
}

func TestConvertDbprotect_CheckResults_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// 8 rows with 6 unique Check IDs: 2986 (2 rows), 2903, 2841, 2801 (2 rows), 2942, 2976
	assert.Len(t, result.Baselines[0].Requirements, 6)
}

// countDistinctCheckIDs parses the raw Cognos XML generically — deliberately NOT
// the converter's structs — and returns the number of distinct "Check ID"
// values across all data rows. It locates the "Check ID" column by its position
// in <metadata><item> and reads the value at that index in each <data><row>.
// The converter emits one requirement per distinct Check ID (rows sharing an id
// are grouped), so the distinct count — not the raw row count — is the ground
// truth.
func countDistinctCheckIDs(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Metadata struct {
			Items []struct {
				Name string `xml:"name,attr"`
			} `xml:"item"`
		} `xml:"metadata"`
		Data struct {
			Rows []struct {
				Values []string `xml:"value"`
			} `xml:"row"`
		} `xml:"data"`
	}
	require.NoError(t, xml.Unmarshal(input, &doc), "failed to parse DBProtect XML for anchor count")

	idx := -1
	for i, item := range doc.Metadata.Items {
		if item.Name == "Check ID" {
			idx = i
			break
		}
	}
	require.GreaterOrEqual(t, idx, 0, "fixture lacks a Check ID column")

	distinct := make(map[string]struct{})
	for _, row := range doc.Data.Rows {
		if idx < len(row.Values) {
			distinct[strings.TrimSpace(row.Values[idx])] = struct{}{}
		}
	}
	return len(distinct)
}

// Ground-truth anchor: one requirement per distinct Check ID. Counted
// independently of the converter so a silent under-extraction fails even when Go
// and TS goldens agree.
func TestConvertDbprotect_CheckResults_DistinctCheckIDAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	shared.AssertRequirementCount(t, result, countDistinctCheckIDs(t, input),
		"sample-check-results.xml: one requirement per distinct Check ID")
}

func TestConvertDbprotect_CheckResults_GroupedResults(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2986 appears twice, should have 2 results
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	assert.Len(t, req.Results, 2)

	// Check ID 2801 appears twice, should have 2 results
	req2801 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	assert.Len(t, req2801.Results, 2)
}

func TestConvertDbprotect_CheckResults_RequirementTitle(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Title)
	assert.Equal(t, "Schema ownership", *req.Title)
}

func TestConvertDbprotect_CheckResults_RequirementDescription(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Descriptions)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	// Description from formatDesc: "Task : <task>; Check Category : <category>"
	assert.Contains(t, req.Descriptions[0].Data, "Task")
	assert.Contains(t, req.Descriptions[0].Data, "Check Category")
}

// ---- Impact mapping ----

func TestConvertDbprotect_CheckResults_HighImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2903")
	assert.Equal(t, 0.7, req.Impact)
}

func TestConvertDbprotect_CheckResults_MediumImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	assert.Equal(t, 0.5, req.Impact)
}

func TestConvertDbprotect_CheckResults_LowImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2841")
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertDbprotect_CheckResults_InformationalImpact(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	assert.Equal(t, 0.0, req.Impact)
}

// ---- Status mapping ----

func TestConvertDbprotect_CheckResults_FactStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2986 has "Fact" status -> Skipped/NotReviewed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_FailedStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2841 has "Failed" status -> Failed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2841")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_FindingStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2801 has "Finding" status -> Failed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_NotAFindingStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2942 has "Not A Finding" status -> Passed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2942")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvertDbprotect_CheckResults_SkippedStatus(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2976 has "Skipped" status -> NotReviewed
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2976")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.NotReviewed, req.Results[0].Status)
}

// ---- Backtrace (heimdall2 Failed-check marker) ----

// getBacktrace mirrors heimdall2: only a literal source "Failed" status yields
// the sentinel marker; every other value (including "Finding", which also maps
// to HDF failed) yields none.
func TestGetBacktrace(t *testing.T) {
	assert.Equal(t, []string{"DB Protect Failed Check"}, getBacktrace("Failed"))
	assert.Nil(t, getBacktrace("Finding"))
	assert.Nil(t, getBacktrace("Not A Finding"))
	assert.Nil(t, getBacktrace(""))
}

// A source "Failed" result carries the heimdall2 backtrace marker.
func TestConvertDbprotect_CheckResults_FailedBacktrace(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2841 has source "Failed" status.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2841")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, []string{"DB Protect Failed Check"}, req.Results[0].Backtrace)
}

// A source "Finding" result maps to HDF failed but is not a literal "Failed", so
// heimdall2 emits no backtrace marker — neither do we.
func TestConvertDbprotect_CheckResults_FindingNoBacktrace(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2801 has source "Finding" status.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2801")
	require.NotEmpty(t, req.Results)
	for _, res := range req.Results {
		assert.Nil(t, res.Backtrace, "Finding results must carry no backtrace marker")
	}
}

// A passing result carries no backtrace marker.
func TestConvertDbprotect_CheckResults_PassNoBacktrace(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Check ID 2942 has source "Not A Finding" status.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2942")
	require.NotEmpty(t, req.Results)
	assert.Nil(t, req.Results[0].Backtrace)
}

// Findings Detail rows are implicitly failed (no Result Status column), so they
// carry no source "Failed" and get no backtrace marker.
func TestConvertDbprotect_FindingsDetail_NoBacktrace(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Nil(t, res.Backtrace, "implicit-failed findings must carry no backtrace marker for check %s", req.ID)
		}
	}
}

// ---- CodeDesc and start time ----

func TestConvertDbprotect_CheckResults_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// CodeDesc comes from the "Details" column
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "Schema name=DatabaseMailUserRole")
}

func TestConvertDbprotect_CheckResults_StartTime(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotEmpty(t, req.Results)
	assert.False(t, req.Results[0].StartTime.IsZero(), "StartTime should be set")
}

// ---- requirement.code (Heimdall CODE tab) ----

// DBProtect ships no literal check source, so requirement.code carries the
// parsed finding row (column→value map) serialized as indented JSON. Keys must
// sort so the bytes match the TypeScript twin.
func TestMarshalFindingCode(t *testing.T) {
	f := finding{
		"Check":          "Schema ownership",
		"Check Category": "Improper Access Controls",
		"Risk DV":        "Medium",
	}
	code := marshalFindingCode(f)

	// Two-space indented, not a compact blob.
	assert.Contains(t, code, "\n  \"Check\": \"Schema ownership\"")

	// Keys emitted in sorted order for byte-parity with the TS twin.
	assert.Less(t, strings.Index(code, `"Check"`), strings.Index(code, `"Check Category"`))
	assert.Less(t, strings.Index(code, `"Check Category"`), strings.Index(code, `"Risk DV"`))

	// Round-trips back to the source row.
	var back map[string]string
	require.NoError(t, json.Unmarshal([]byte(code), &back))
	assert.Equal(t, map[string]string(f), back)
}

// An empty row serializes to the empty object rather than "null" — the normal
// encode path, no separate guard.
func TestMarshalFindingCode_Empty(t *testing.T) {
	assert.Equal(t, "{}", marshalFindingCode(finding{}))
}

func TestConvertDbprotect_CheckResults_RequirementCode(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Code, "requirement.code must be populated for the CODE tab")

	var row map[string]string
	require.NoError(t, json.Unmarshal([]byte(*req.Code), &row))
	assert.Equal(t, "Schema ownership", row["Check"])
	assert.Equal(t, "Improper Access Controls", row["Check Category"])
	assert.Equal(t, "Medium", row["Risk DV"])
	assert.Equal(t, "Schema name=DatabaseMailUserRole;Database=msdb;Owner name=DatabaseMailUserRole", row["Details"])
}

// The Findings Detail report (no Result Status column) also populates code.
func TestConvertDbprotect_FindingsDetail_RequirementCode(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		require.NotNil(t, req.Code, "requirement %q must carry code", req.ID)
		var row map[string]string
		require.NoError(t, json.Unmarshal([]byte(*req.Code), &row))
		assert.NotEmpty(t, row["Check"])
	}
}

// ---- NIST tags ----

func TestConvertDbprotect_CheckResults_NISTTags(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Tags)
	nist, ok := req.Tags["nist"]
	require.True(t, ok, "Should have nist tag")
	nistSlice := hdfutil.SafeStringSlice(nist)
	assert.NotEmpty(t, nistSlice, "NIST tags should not be empty")
}

// ---- check_category tag ----

// The "Check Category" column is DBProtect's finding classification; it is
// surfaced as the check_category tag, present in both report formats.
func TestConvertDbprotect_CheckResults_CheckCategoryTag(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2986")
	require.NotNil(t, req.Tags)
	assert.Equal(t, "Improper Access Controls", req.Tags["check_category"])

	req2903 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2903")
	assert.Equal(t, "Misconfigurations", req2903.Tags["check_category"])
}

func TestConvertDbprotect_FindingsDetail_CheckCategoryTag(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "2903")
	assert.Equal(t, "Misconfigurations", req.Tags["check_category"])
}

// Absent branch: a finding with no Check Category value omits the tag entirely.
func TestBuildRequirement_CheckCategoryAbsent(t *testing.T) {
	req := buildRequirement("999", []finding{{"Check": "x", "Risk DV": "Low"}}, false)
	_, present := req.Tags["check_category"]
	assert.False(t, present, "check_category tag must be omitted when source field is absent")
}

// ---- Scan target component (database identity) ----

// The scan target is a database asset built from the "IP Address, Port,
// Instance" cell plus "Asset Type" (engine) and "Asset" (host name). Name is
// the instance.
func TestConvertDbprotect_CheckResults_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.Database, comp.Type)
	assert.Equal(t, "MSSQLSERVER", comp.Name)

	require.NotNil(t, comp.IPAddress)
	assert.Equal(t, "10.0.10.204", *comp.IPAddress)
	require.NotNil(t, comp.Port)
	assert.Equal(t, int64(1433), *comp.Port)
	require.NotNil(t, comp.Engine)
	assert.Equal(t, "Microsoft SQL Server", *comp.Engine)
	require.NotNil(t, comp.Hostname)
	assert.Equal(t, "CONDS181", *comp.Hostname)
}

func TestConvertDbprotect_FindingsDetail_Target(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Components, 1)
	comp := result.Components[0]
	assert.Equal(t, hdf.Database, comp.Type)
	assert.Equal(t, "MSSQLSERVER", comp.Name)
	require.NotNil(t, comp.IPAddress)
	assert.Equal(t, "192.168.1.200", *comp.IPAddress)
	require.NotNil(t, comp.Hostname)
	assert.Equal(t, "HOST1", *comp.Hostname)
}

// parseTarget splits the combined identity cell; missing parts come back empty.
func TestParseTarget(t *testing.T) {
	ip, port, instance := parseTarget("10.0.10.204, 1433, MSSQLSERVER")
	assert.Equal(t, "10.0.10.204", ip)
	assert.Equal(t, "1433", port)
	assert.Equal(t, "MSSQLSERVER", instance)

	ip, port, instance = parseTarget("10.0.10.204, 1433")
	assert.Equal(t, "10.0.10.204", ip)
	assert.Equal(t, "1433", port)
	assert.Empty(t, instance)

	ip, port, instance = parseTarget("")
	assert.Empty(t, ip)
	assert.Empty(t, port)
	assert.Empty(t, instance)
}

// Name falls back to IP:Port when no instance is present.
func TestBuildScanTarget_NameFallsBackToIPPort(t *testing.T) {
	comp := buildScanTarget(finding{"IP Address, Port, Instance": "10.0.10.204, 1433"})
	require.NotNil(t, comp)
	assert.Equal(t, "10.0.10.204:1433", comp.Name)
	assert.Equal(t, hdf.Database, comp.Type)
}

// Name falls back to IP alone when there is neither instance nor port.
func TestBuildScanTarget_NameFallsBackToIP(t *testing.T) {
	comp := buildScanTarget(finding{"IP Address, Port, Instance": "10.0.10.204"})
	require.NotNil(t, comp)
	assert.Equal(t, "10.0.10.204", comp.Name)
	assert.Nil(t, comp.Port)
}

// Name falls back to the raw Asset label when the identity cell is empty.
func TestBuildScanTarget_NameFallsBackToAsset(t *testing.T) {
	comp := buildScanTarget(finding{"Asset": "CONDS181"})
	require.NotNil(t, comp)
	assert.Equal(t, "CONDS181", comp.Name)
	assert.Nil(t, comp.IPAddress)
	require.NotNil(t, comp.Hostname)
	assert.Equal(t, "CONDS181", *comp.Hostname)
}

// A non-numeric port is dropped rather than emitted as a bogus value.
func TestBuildScanTarget_NonNumericPortDropped(t *testing.T) {
	comp := buildScanTarget(finding{"IP Address, Port, Instance": "10.0.10.204, abc, INST"})
	require.NotNil(t, comp)
	assert.Equal(t, "INST", comp.Name)
	assert.Nil(t, comp.Port)
}

// Absent branch: no identity columns at all -> no component (NOT-IN-SOURCE).
func TestBuildScanTarget_AbsentReturnsNil(t *testing.T) {
	assert.Nil(t, buildScanTarget(finding{}))
	assert.Nil(t, buildScanTarget(finding{"Check": "x"}))
}

// ---- Findings Detail fixture ----

func TestConvertDbprotect_FindingsDetail_BasicStructure(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.Baselines, 1)
	assert.Equal(t, "DBProtect Scan", result.Baselines[0].Name)
}

func TestConvertDbprotect_FindingsDetail_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// 4 rows with 3 unique Check IDs: 2801 (2 rows), 2830, 2903
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertDbprotect_FindingsDetail_AllFindingsAreFailed(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	// Findings Detail has no Result Status column; all findings are implicitly failed
	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, hdf.Failed, res.Status, "All findings should be failed for check %s", req.ID)
		}
	}
}

// ---- Write output for differential testing ----

func TestConvertDbprotect_WriteOutput(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	shared.WriteOutput(t, "dbprotect-to-hdf", "sample-check-results.json", result)
}

func TestConvertDbprotectToHDF_EntityExpansion(t *testing.T) {
	input := []byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test">]><foo/>`)
	_, err := ConvertDbprotectToHDF(input, testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "entity declarations")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "dbprotect-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertDbprotectToHDF(input, "1.0.0")
	})
}

// ---- Top-level timestamp (source-derived, value-pinned) ----

// The snapshot harness masks the top-level timestamp, so the golden does not
// verify its value. Pin the exact source-derived value here: the Findings Detail
// report carries a "Start Date" column, which becomes the top-level timestamp.
func TestConvertDbprotect_FindingsDetail_TimestampFromStartDate(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp, "timestamp must be populated from Start Date")
	assert.Equal(t, "2021-02-18T15:55:00Z", result.Timestamp.UTC().Format(time.RFC3339))
}

// Fallback branch: the Check Results report has no "Start Date" column, so the
// top-level timestamp falls back to the per-finding "Date" column.
func TestConvertDbprotect_CheckResults_TimestampFallsBackToDate(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp, "timestamp must fall back to the Date column")
	assert.Equal(t, "2021-02-18T15:57:00Z", result.Timestamp.UTC().Format(time.RFC3339))
}

// Determinism: converting the same input twice yields the identical top-level
// timestamp (source-derived, never now()).
func TestConvertDbprotect_TimestampDeterministic(t *testing.T) {
	input := loadFixture(t, "input/sample-findings-detail.xml")
	first, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)
	second, err := ConvertDbprotectToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, first.Timestamp)
	require.NotNil(t, second.Timestamp)
	assert.Equal(t, first.Timestamp.UTC(), second.Timestamp.UTC())
}

// scanTimestamp derivation, exercised directly to cover every branch.
func TestScanTimestamp(t *testing.T) {
	// Start Date preferred when present.
	assert.Equal(t, "2021-02-18T15:55:00Z",
		scanTimestamp(finding{"Start Date": "2021-02-18 15:55", "Date": "Feb 18 2021 15:57"}).UTC().Format(time.RFC3339))

	// Falls back to Date when Start Date is absent.
	assert.Equal(t, "2021-02-18T15:57:00Z",
		scanTimestamp(finding{"Date": "Feb 18 2021 15:57"}).UTC().Format(time.RFC3339))

	// Zero time when neither is parseable, so the caller omits the timestamp.
	assert.True(t, scanTimestamp(finding{}).IsZero())
}

func TestConvertDbprotect_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/sample-check-results.xml")
	result, err := ConvertDbprotectToHDF(input, testVersion)
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
