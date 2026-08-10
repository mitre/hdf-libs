package zap_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
		ConverterName:  "zap-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertZapToHDF(input, testConverterVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertZapToHDF_MissingSiteArray(t *testing.T) {
	input := []byte(`{"@version": "2.7.0"}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "zap-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "OWASP ZAP")
}

func TestConvertZapToHDF_EmptySiteArray(t *testing.T) {
	input := []byte(`{"@version": "2.7.0", "site": []}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "zap-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "OWASP ZAP")
}

func TestConvertZapToHDF_EmptyFindings(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "zap-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "OWASP ZAP")
	assert.Contains(t, req.Results[0].CodeDesc, "https://example.com")
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
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
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
	assert.Equal(t, hdf.Application, result.Components[0].Type)
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertZapToHDF_ImpactRiskCode2(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
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

	req1 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Len(t, req1.Results, 1)

	req2 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, "URI: https://example.com/login | Method: GET | Param: X-Content-Type-Options", req.Results[0].CodeDesc)
}

func TestConvertZapToHDF_AttackMessage(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req.Results[1].Message)
	assert.Equal(t, "' OR 1=1 --", *req.Results[1].Message)
}

// --- Requirement code (CODE tab) ---
// requirement.code is synthesized from the HTTP request context of the alert's
// representative instance: "<METHOD> <uri>" + optional "Param: <param>" +
// optional "Attack: <attack>". The representative instance is the first instance
// carrying an attack payload (falling back to the first instance otherwise), so
// the DAST payload surfaces on the CODE tab even when it is not on instance[0].

func TestConvertZapToHDF_RequirementCode_FallbackFirstInstance(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// 10021: no instance carries an attack, so the first instance is used.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req.Code)
	assert.Equal(t, "GET https://example.com/login\nParam: X-Content-Type-Options", *req.Code)
}

func TestConvertZapToHDF_RequirementCode_PrefersAttackInstance(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// 90022: instance[0] has no attack; instance[1] carries the SQLi payload, so
	// that instance is chosen and the attack surfaces on the CODE tab.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req.Code)
	assert.Equal(t, "POST https://example.com/api/login\nParam: username\nAttack: ' OR 1=1 --", *req.Code)
}

func Test_representativeInstance(t *testing.T) {
	_, ok := representativeInstance(nil)
	assert.False(t, ok, "no instances → not ok")

	first := ZapInstance{Method: "GET", URI: "/a"}
	second := ZapInstance{Method: "POST", URI: "/b", Attack: "x"}
	got, ok := representativeInstance([]ZapInstance{first, second})
	require.True(t, ok)
	assert.Equal(t, second, got, "instance carrying an attack is preferred")

	got, ok = representativeInstance([]ZapInstance{first})
	require.True(t, ok)
	assert.Equal(t, first, got, "falls back to the first instance when none carry an attack")
}

func Test_buildRequirementCode(t *testing.T) {
	// NOT-IN-SOURCE: no instances at all → code left unset.
	assert.Nil(t, buildRequirementCode(ZapAlert{}))

	// NOT-IN-SOURCE: an instance with no request context → code left unset.
	assert.Nil(t, buildRequirementCode(ZapAlert{Instances: []ZapInstance{{}}}))

	// Request line only (no param, no attack).
	code := buildRequirementCode(ZapAlert{Instances: []ZapInstance{{Method: "GET", URI: "/x"}}})
	require.NotNil(t, code)
	assert.Equal(t, "GET /x", *code)

	// Param only — no method/uri, so no request line.
	code = buildRequirementCode(ZapAlert{Instances: []ZapInstance{{Param: "p"}}})
	require.NotNil(t, code)
	assert.Equal(t, "Param: p", *code)

	// Attack only — no method/uri/param.
	code = buildRequirementCode(ZapAlert{Instances: []ZapInstance{{Attack: "a"}}})
	require.NotNil(t, code)
	assert.Equal(t, "Attack: a", *code)

	// Full request context.
	code = buildRequirementCode(ZapAlert{Instances: []ZapInstance{{Method: "POST", URI: "/y", Param: "q", Attack: "z"}}})
	require.NotNil(t, code)
	assert.Equal(t, "POST /y\nParam: q\nAttack: z", *code)
}

// --- NIST mapping ---

func TestConvertZapToHDF_NISTMappedCWE(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")

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

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")

	cciVal, ok := req.Tags["cci"]
	require.True(t, ok, "cci tag missing")
	cciSlice, ok := cciVal.([]interface{})
	require.True(t, ok, "cci tag not a slice")
	assert.Greater(t, len(cciSlice), 0)
}

// --- Extra tags ---

func TestConvertZapToHDF_CWEFirstClass(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, []string{"CWE-16"}, req.Cwe)
	// The CWE is now first-class only — it must not linger as a tag.
	_, ok := req.Tags["cweid"]
	assert.False(t, ok, "cweid tag must be removed once promoted to cwe[]")
}

func TestConvertZapToHDF_CWEAbsentWhenEmpty(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Alert 90022 in minimal.json carries an empty cweid → no cwe[] emitted.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	assert.Nil(t, req.Cwe)
	_, ok := req.Tags["cweid"]
	assert.False(t, ok)
}

func TestConvertZapToHDF_WASCIDTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, "15", req.Tags["wascid"])
}

func TestConvertZapToHDF_RiskDescTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, "Low (Medium)", req.Tags["riskdesc"])
}

func TestConvertZapToHDF_ConfidenceTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, "2", req.Tags["confidence"])
}

// sourceid is ZAP's alert source identifier; it is emitted as a tag (value-pinned).
func TestConvertZapToHDF_SourceIDTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	assert.Equal(t, "3", req.Tags["sourceid"])

	req2 := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	assert.Equal(t, "5", req2.Tags["sourceid"])
}

// An alert with no sourceid emits no sourceid tag (absent branch).
func TestConvertZapToHDF_SourceIDTagAbsent(t *testing.T) {
	input := []byte(`{"@version":"2.7.0","site":[{"@host":"h","alerts":[{"pluginid":"1","name":"n"}]}]}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	_, ok := req.Tags["sourceid"]
	assert.False(t, ok, "no sourceid on the alert -> no sourceid tag")
}

// --- Result start_time ---
// ZAP carries no per-finding scan time, so each result's start_time is
// backfilled from the report's @generated timestamp (value-pinned).

func TestConvertZapToHDF_ResultStartTime(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.Len(t, req.Results, 1)
	assert.Equal(t, "2018-12-06T10:53:11Z", req.Results[0].StartTime.UTC().Format(time.RFC3339))
}

// Every result across every alert shares the single @generated time.
func TestConvertZapToHDF_ResultStartTimeUniform(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		for _, res := range req.Results {
			assert.Equal(t, "2018-12-06T10:53:11Z", res.StartTime.UTC().Format(time.RFC3339),
				"requirement %q result start_time backfilled from @generated", req.ID)
		}
	}
}

// When the report has no parseable @generated, results fall back to the zero time.
func TestConvertZapToHDF_ResultStartTimeFallbackZero(t *testing.T) {
	input := []byte(`{"@version":"2.7.0","site":[{"@host":"h","alerts":[{"pluginid":"1","name":"n","instances":[{"uri":"/x"}]}]}]}`)
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Results, 1)
	assert.True(t, req.Results[0].StartTime.IsZero(), "no @generated -> zero-time start_time")
}

// --- Descriptions ---

func TestConvertZapToHDF_DefaultDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.Len(t, req.Descriptions, 3)
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.NotContains(t, req.Descriptions[0].Data, "<p>")
	assert.Contains(t, req.Descriptions[0].Data, "X-Content-Type-Options was not set to 'nosniff'")
}

// solution is ZAP's remediation guidance, homed under its own "solution" label
// with the HTML stripped (value-pinned).
func TestConvertZapToHDF_SolutionDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.Len(t, req.Descriptions, 3)
	assert.Equal(t, "solution", req.Descriptions[1].Label)
	assert.Equal(t, "Ensure that the application/web server sets the Content-Type header appropriately.", req.Descriptions[1].Data)
}

// otherinfo stays under the "check" label; it no longer carries the solution text.
func TestConvertZapToHDF_CheckDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.Len(t, req.Descriptions, 3)
	assert.Equal(t, "check", req.Descriptions[2].Label)
	assert.Equal(t, "This issue still applies to error type pages.", req.Descriptions[2].Data)
	assert.NotContains(t, req.Descriptions[2].Data, "Content-Type header")
}

// When an alert carries no otherinfo, no "check" description is emitted; the
// solution still lands as its own description.
func TestConvertZapToHDF_SolutionWithoutOtherInfo(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Alert 90022 in minimal.json has an empty otherinfo but a solution.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	labels := make([]string, len(req.Descriptions))
	for i, d := range req.Descriptions {
		labels[i] = d.Label
	}
	assert.Equal(t, []string{"default", "solution"}, labels)
	assert.Equal(t, "Review the source code.", req.Descriptions[1].Data)
}

// --- External references (refs[]) ---

// alert.reference is HTML-wrapped URLs; each real URL becomes a refs[] entry
// (value-pinned).
func TestConvertZapToHDF_Refs(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx", *req.Refs[0].URL)
}

// An empty reference field emits no refs[] (absent branch).
func TestConvertZapToHDF_RefsAbsent(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// Alert 90022 in minimal.json has an empty reference.
	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	assert.Nil(t, req.Refs)
}

func Test_buildRefs(t *testing.T) {
	assert.Nil(t, buildRefs(""), "empty reference -> nil")
	assert.Nil(t, buildRefs("<p></p>"), "markup with no URL -> nil")

	// Multiple <p>-wrapped URLs -> one Reference each, in order.
	refs := buildRefs("<p>http://a.example/x</p><p>https://b.example/y</p>")
	require.Len(t, refs, 2)
	assert.Equal(t, "http://a.example/x", *refs[0].URL)
	assert.Equal(t, "https://b.example/y", *refs[1].URL)

	// An anchor tag: the href URL is pulled from the markup.
	refs = buildRefs(`<a href="https://c.example/z">c</a>`)
	require.Len(t, refs, 1)
	assert.Equal(t, "https://c.example/z", *refs[0].URL)

	// Whitespace-separated plain URLs.
	refs = buildRefs("https://d.example/1 https://e.example/2")
	require.Len(t, refs, 2)
	assert.Equal(t, "https://d.example/1", *refs[0].URL)
	assert.Equal(t, "https://e.example/2", *refs[1].URL)
}

// --- Source location ---
// requirement.sourceLocation promotes the affected URL of the alert's primary
// (first uri-bearing) instance into the structured, queryable HDF locus. ZAP is
// a DAST tool, so ref is a URL and line is always omitted. The URL still appears
// in codeDesc freetext — sourceLocation is an additive structured field.

func TestConvertZapToHDF_SourceLocation(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "10021")
	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "https://example.com/login", *req.SourceLocation.Ref)
	assert.Nil(t, req.SourceLocation.Line, "DAST URL locus carries no line")
}

// The primary instance is the first uri-bearing instance; alert 90022 has two
// instances and the first one's uri is used.
func TestConvertZapToHDF_SourceLocationFirstInstance(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "90022")
	require.NotNil(t, req.SourceLocation)
	require.NotNil(t, req.SourceLocation.Ref)
	assert.Equal(t, "https://example.com/api/submit", *req.SourceLocation.Ref)
}

func Test_buildSourceLocation(t *testing.T) {
	// NOT-IN-SOURCE: no instances at all → sourceLocation omitted.
	assert.Nil(t, buildSourceLocation(ZapAlert{}))

	// Absent branch: an instance with no uri → sourceLocation omitted.
	assert.Nil(t, buildSourceLocation(ZapAlert{Instances: []ZapInstance{{Method: "GET"}}}))

	// A uri-bearing instance → ref set, line omitted.
	loc := buildSourceLocation(ZapAlert{Instances: []ZapInstance{{URI: "https://x.example/a"}}})
	require.NotNil(t, loc)
	require.NotNil(t, loc.Ref)
	assert.Equal(t, "https://x.example/a", *loc.Ref)
	assert.Nil(t, loc.Line)

	// First uri-bearing instance wins when earlier instances lack a uri.
	loc = buildSourceLocation(ZapAlert{Instances: []ZapInstance{{Method: "GET"}, {URI: "https://x.example/b"}}})
	require.NotNil(t, loc)
	require.NotNil(t, loc.Ref)
	assert.Equal(t, "https://x.example/b", *loc.Ref)
}

// --- SARIF routing ---

func TestConvertZapToHDF_SARIFInput(t *testing.T) {
	// SARIF input should be transparently delegated to the SARIF converter
	sarifInput := []byte(`{"$schema":"test","version":"2.1.0","runs":[{"tool":{"driver":{"name":"Test","version":"1.0"}},"results":[]}]}`)
	result, err := ConvertZapToHDF(sarifInput, testConverterVersion)
	require.NoError(t, err)
	assert.NotEqual(t, "OWASP ZAP Scan", result.Baselines[0].Name)
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

func Test_buildCwe(t *testing.T) {
	assert.Equal(t, []string{"CWE-16"}, buildCwe("16"))
	assert.Equal(t, []string{"CWE-200"}, buildCwe("200"))
	assert.Nil(t, buildCwe(""))
	assert.Nil(t, buildCwe("0"))
	assert.Nil(t, buildCwe("abc"))
}

// --- StripHTML ---

func Test_stripHTML(t *testing.T) {
	assert.Equal(t, "Hello world", hdfutil.StripHTML("<p>Hello</p><p>world</p>"))
	assert.Equal(t, "plain text", hdfutil.StripHTML("plain text"))
	assert.Equal(t, "", hdfutil.StripHTML(""))
}

// --- Webgoat fixture ---
// webgoat.json: ZAP scan results from the OWASP WebGoat deliberately vulnerable application.
// Contains 4 sites: mymac.com (25 alerts, 15 unique plugin IDs) plus 3 single-alert
// hosts (ciscobinary.openh264.org, code.jquery.com, detectportal.firefox.com). Every
// site is converted to its own baseline + Application component (see multi-site tests).

// mymacBaseline returns the per-site baseline for host mymac.com, the busiest site.
func mymacBaseline(t *testing.T, result *hdf.HDFResults) hdf.EvaluatedBaseline {
	t.Helper()
	for _, b := range result.Baselines {
		if b.Labels["component"] == "mymac.com" {
			return b
		}
	}
	t.Fatalf("no baseline for host mymac.com")
	return hdf.EvaluatedBaseline{}
}

// Every site becomes its own baseline + Application component — no site is dropped.
func TestConvertZapToHDF_Webgoat_AllSitesConverted(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 4, "one baseline per ZAP site")
	require.Len(t, result.Components, 4, "one Application component per ZAP site")

	hosts := make(map[string]bool)
	for _, c := range result.Components {
		assert.Equal(t, hdf.Application, c.Type)
		hosts[c.Name] = true
	}
	assert.True(t, hosts["mymac.com"], "mymac.com component present")
	assert.True(t, hosts["ciscobinary.openh264.org"], "ciscobinary component present")
	assert.True(t, hosts["code.jquery.com"], "code.jquery.com component present")
	assert.True(t, hosts["detectportal.firefox.com"], "detectportal component present")
}

// Each per-site baseline is linked to its host component via the "component" label,
// and carries a unique, host-scoped name.
func TestConvertZapToHDF_Webgoat_BaselineHostAttribution(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, b := range result.Baselines {
		host := b.Labels["component"]
		require.NotEmpty(t, host, "baseline %q missing component label", b.Name)
		assert.False(t, names[b.Name], "baseline name %q is not unique", b.Name)
		names[b.Name] = true
		assert.Contains(t, b.Name, host, "baseline name should identify its host")
	}
}

func TestConvertZapToHDF_Webgoat_RequirementCount(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	// mymac.com carries 25 alerts, each its own requirement (duplicates get .1, .2, ...).
	assert.Len(t, mymacBaseline(t, result).Requirements, 25)
}

// The 3 single-alert hosts all share pluginid 10021. Per-site baselines keep that
// finding as "10021" in each host's baseline — no cross-site dedup suffixing.
func TestConvertZapToHDF_Webgoat_CrossSitePluginIDNotConflated(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	seen := 0
	for _, b := range result.Baselines {
		host := b.Labels["component"]
		if host == "mymac.com" {
			continue
		}
		require.Len(t, b.Requirements, 1, "single-alert host %q", host)
		assert.Equal(t, "10021", b.Requirements[0].ID,
			"host %q keeps pluginid 10021 undeduped", host)
		seen++
	}
	assert.Equal(t, 3, seen, "three single-alert hosts")
}

func TestConvertZapToHDF_Webgoat_Deduplication(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	reqs := mymacBaseline(t, result).Requirements
	ids := make([]string, len(reqs))
	for i, req := range reqs {
		ids[i] = req.ID
	}

	// 90028 appears many times within mymac.com
	assert.Contains(t, ids, "90028")
	assert.Contains(t, ids, "90028.1")
	assert.Contains(t, ids, "90028.2")
}

func TestConvertZapToHDF_Webgoat_ImpactRisk0(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, mymacBaseline(t, result).Requirements, "90028")
	assert.Equal(t, 0.3, req.Impact)
}

func TestConvertZapToHDF_Webgoat_ImpactRisk3(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, mymacBaseline(t, result).Requirements, "42")
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

func TestConvertZapToHDF_ControlType(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)

	var sawDerivation bool
	for _, b := range result.Baselines {
		for _, req := range b.Requirements {
			if req.ControlType != nil {
				sawDerivation = true
				switch *req.ControlType {
				case hdf.Management, hdf.Operational, hdf.Technical, hdf.Policy, hdf.Procedure:
				default:
					t.Errorf("requirement %q has unrecognized controlType %q", req.ID, *req.ControlType)
				}
			}
		}
	}
	assert.True(t, sawDerivation, "at least one requirement should derive controlType")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "zap-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertZapToHDF(input, "1.0.0")
	})
}

// countAllSiteAlerts parses raw ZAP JSON generically — NOT via the converter's
// parser — and returns the total alert count across EVERY site. The converter
// emits one requirement per alert of every site (the pluginid dedup only
// uniquifies IDs within a site, it does not collapse alerts), so a silent
// per-site drop fails this anchor even when Go/TS golden parity agrees.
func countAllSiteAlerts(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Site []struct {
			Alerts []json.RawMessage `json:"alerts"`
		} `json:"site"`
	}
	require.NoError(t, json.Unmarshal(input, &doc), "failed to parse zap JSON for anchor count")
	total := 0
	for _, s := range doc.Site {
		total += len(s.Alerts)
	}
	return total
}

// Ground-truth anchor: the converter emits one requirement per alert of EVERY
// site. The count is derived independently of the converter's parser, so a
// silent per-site drop fails even when Go/TS golden parity agrees. webgoat.json
// carries 28 alerts across all 4 sites (the old single-site behavior dropped 3).
func TestConvertZapToHDF_AllSiteAlertAnchor(t *testing.T) {
	input := loadFixture(t, "input/webgoat.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, countAllSiteAlerts(t, input),
		"webgoat.json: one requirement per alert across all sites")
}

func TestConvertZapToHDF_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertZapToHDF(input, testConverterVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q expected verificationMethod=automated", req.ID)
	}
}
