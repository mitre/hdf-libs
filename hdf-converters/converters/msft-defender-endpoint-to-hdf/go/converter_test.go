package msftdefenderendpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

// ---- Error handling ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "msft-defender-endpoint-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftDefenderEndpointToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvert_MissingValueArray(t *testing.T) {
	_, err := ConvertMsftDefenderEndpointToHDF([]byte(`{"foo": "bar"}`), testVersion)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing or invalid value array")
}

// ---- Minimal fixture conversion ----

func TestConvert_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Minimal fixture has 1 alert → 1 requirement
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 1)
}

// ---- Sample fixture conversion ----

func TestConvert_Sample(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Sample fixture has 4 alerts → 4 requirements
	assert.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 4)
}

// ---- Status mapping ----

func TestConvert_StatusMapping_New(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.json has status "new" → Failed
	req := result.Baselines[0].Requirements[0]
	assert.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvert_StatusMapping_InProgress(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Second alert in sample.json has status "inProgress" → Failed
	req := result.Baselines[0].Requirements[1]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

func TestConvert_StatusMapping_Resolved_FalsePositive(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert: resolved with classification "falsePositive" → Passed
	req := result.Baselines[0].Requirements[2]
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvert_StatusMapping_Resolved_TruePositive(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Fourth alert: resolved with classification "truePositive" → Failed
	req := result.Baselines[0].Requirements[3]
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

// ---- Severity mapping ----

func TestConvert_SeverityMapping_High(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// First alert: severity "high" → 0.7
	assert.Equal(t, 0.7, result.Baselines[0].Requirements[0].Impact)
}

func TestConvert_SeverityMapping_Medium(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Second alert: severity "medium" → 0.5
	assert.Equal(t, 0.5, result.Baselines[0].Requirements[1].Impact)
}

func TestConvert_SeverityMapping_Low(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// minimal.json: severity "low" → 0.3
	assert.Equal(t, 0.3, result.Baselines[0].Requirements[0].Impact)
}

func TestConvert_SeverityMapping_Informational(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert: severity "informational" → 0.0
	assert.Equal(t, 0.0, result.Baselines[0].Requirements[2].Impact)
}

// ---- Generator name ----

func TestConvert_GeneratorName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-defender-endpoint-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvert_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Defender for Endpoint", *result.Tool.Name)
}

// ---- Target: Host from device evidence ----

func TestConvert_Target_Host(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	target := result.Components[0]
	assert.Equal(t, hdf.Host, target.Type)
	assert.Equal(t, "temp123.middleeast.corp.microsoft.com", target.Name)
	require.NotNil(t, target.FQDN)
	assert.Equal(t, "temp123.middleeast.corp.microsoft.com", *target.FQDN)
	require.NotNil(t, target.OSName)
	assert.Equal(t, "Windows10", *target.OSName)
}

func TestConvert_Target_Deduplicated(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// 4 alerts with 4 different devices → 4 targets
	assert.Len(t, result.Components, 4)
}

// ---- MITRE ATT&CK techniques in tags ----

func TestConvert_MitreTechniques(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	mitre, ok := req.Tags["mitre"].([]interface{})
	require.True(t, ok, "mitre tag should be a slice")
	assert.Len(t, mitre, 3)
	assert.Contains(t, mitre, "T1064")
	assert.Contains(t, mitre, "T1085")
	assert.Contains(t, mitre, "T1220")
}

func TestConvert_NoMitreTechniques(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Third alert has empty mitreTechniques
	req := result.Baselines[0].Requirements[2]
	_, hasMitre := req.Tags["mitre"]
	assert.False(t, hasMitre, "should not have mitre tag when no techniques")
}

// ---- Category tag ----

func TestConvert_CategoryTag(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "Execution", req.Tags["category"])
}

// ---- Descriptions ----

func TestConvert_Descriptions(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Len(t, req.Descriptions, 2)

	// Default description from alert description
	assert.Equal(t, "default", req.Descriptions[0].Label)
	assert.Contains(t, req.Descriptions[0].Data, "Binaries signed by Microsoft")

	// Fix description from recommendedActions
	assert.Equal(t, "fix", req.Descriptions[1].Label)
	assert.Contains(t, req.Descriptions[1].Data, "Collect artifacts")
}

// ---- Refs from alertWebUrl ----

func TestConvert_Refs_FromAlertWebURL(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://security.microsoft.com/alerts/da637472900382838869_1364969609", *req.Refs[0].URL)
	assert.Nil(t, req.Refs[0].URI)
	assert.Nil(t, req.Refs[0].Ref)
}

func TestConvert_Refs_Absent(t *testing.T) {
	// empty.json → no alerts → the no-findings requirement carries no alertWebUrl → no refs.
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Empty(t, req.Refs)
}

// ---- Evidence in code_desc ----

func TestConvert_EvidenceInCodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	codeDesc := req.Results[0].CodeDesc
	assert.Contains(t, codeDesc, "Device: temp123.middleeast.corp.microsoft.com")
	assert.Contains(t, codeDesc, "Process:")
	assert.Contains(t, codeDesc, "rundll32.exe")
}

// ---- Classification/determination tags ----

func TestConvert_ClassificationDetermination(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Fourth alert has classification and determination
	req := result.Baselines[0].Requirements[3]
	assert.Equal(t, "truePositive", req.Tags["classification"])
	assert.Equal(t, "malware", req.Tags["determination"])
}

// ---- Source metadata tags (incident_id, detection_source, service_source, threat_family_name) ----

func TestConvert_IncidentIDTag(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// incidentId "1126093" is a canonical integer → emitted as a number.
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, int64(1126093), req.Tags["incident_id"])
}

func TestConvert_IncidentIDTag_NonNumericFallsBackToString(t *testing.T) {
	// A non-numeric incidentId is preserved verbatim as a string.
	doc := `{"value":[{"id":"a","incidentId":"INC-42","status":"new","severity":"low",` +
		`"category":"Execution","title":"t","description":"d"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "INC-42", req.Tags["incident_id"])
}

func TestConvert_IncidentIDTag_Absent(t *testing.T) {
	// Missing incidentId → no incident_id tag.
	doc := `{"value":[{"id":"a","status":"new","severity":"low",` +
		`"category":"Execution","title":"t","description":"d"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	_, has := req.Tags["incident_id"]
	assert.False(t, has, "should omit incident_id when absent")
}

func TestConvert_DetectionAndServiceSourceTags(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "WindowsDefenderAtp", req.Tags["detection_source"])
	assert.Equal(t, "microsoftDefenderForEndpoint", req.Tags["service_source"])

	// Fourth alert has a different detectionSource.
	assert.Equal(t, "WindowsDefenderAv", result.Baselines[0].Requirements[3].Tags["detection_source"])
}

func TestConvert_DetectionAndServiceSourceTags_Absent(t *testing.T) {
	doc := `{"value":[{"id":"a","incidentId":"1","status":"new","severity":"low",` +
		`"category":"Execution","title":"t","description":"d"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	_, hasDet := req.Tags["detection_source"]
	_, hasSvc := req.Tags["service_source"]
	assert.False(t, hasDet, "should omit detection_source when absent")
	assert.False(t, hasSvc, "should omit service_source when absent")
}

func TestConvert_ThreatFamilyNameTag(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Fourth alert carries threatFamilyName "Emotet".
	assert.Equal(t, "Emotet", result.Baselines[0].Requirements[3].Tags["threat_family_name"])
}

func TestConvert_ThreatFamilyNameTag_AbsentWhenNull(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// First alert has threatFamilyName: null → tag omitted.
	req := result.Baselines[0].Requirements[0]
	_, has := req.Tags["threat_family_name"]
	assert.False(t, has, "should omit threat_family_name when source is null")
}

func TestConvert_ActorDisplayNameNotMapped(t *testing.T) {
	// actorDisplayName is null in every fixture — it must never be tagged.
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	for _, req := range result.Baselines[0].Requirements {
		_, has := req.Tags["actor_display_name"]
		assert.False(t, has, "actor_display_name must not be emitted (NOT-IN-SOURCE)")
	}
}

// ---- Checksum ----

func TestConvert_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Alert ID as requirement ID ----

func TestConvert_AlertIDAsRequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "da637472900382838869_1364969609", req.ID)
}

// ---- Empty value array ----

func TestConvert_EmptyValueArray(t *testing.T) {
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "msft-defender-endpoint-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Microsoft Defender for Endpoint")
	assert.Contains(t, req.Results[0].CodeDesc, "zero findings")
}

// ---- Helper: severityToImpact ----

func TestSeverityToImpact(t *testing.T) {
	tests := []struct {
		severity string
		expected float64
	}{
		{"high", 0.7},
		{"High", 0.7},
		{"medium", 0.5},
		{"low", 0.3},
		{"informational", 0.0},
		{"unknown", 0.5},
	}
	for _, tc := range tests {
		t.Run(tc.severity, func(t *testing.T) {
			assert.Equal(t, tc.expected, severityToImpact(tc.severity))
		})
	}
}

// ---- Helper: statusToResult ----

func TestStatusToResult(t *testing.T) {
	falsePos := "falsePositive"
	truePos := "truePositive"

	tests := []struct {
		name           string
		status         string
		classification *string
		expected       hdf.ResultStatus
	}{
		{"new", "new", nil, hdf.Failed},
		{"inProgress", "inProgress", nil, hdf.Failed},
		{"resolved_falsePositive", "resolved", &falsePos, hdf.Passed},
		{"resolved_truePositive", "resolved", &truePos, hdf.Failed},
		{"resolved_nil", "resolved", nil, hdf.Failed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, statusToResult(tc.status, tc.classification))
		})
	}
}

// ---- Verify JSON round-trip ----

func TestConvert_JSONRoundTrip(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// Marshal to JSON and back to verify structure is valid
	jsonBytes, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotEmpty(t, jsonBytes)

	var roundTrip hdf.HDFResults
	err = json.Unmarshal(jsonBytes, &roundTrip)
	require.NoError(t, err)
	assert.Len(t, roundTrip.Baselines, 1)
	assert.Len(t, roundTrip.Baselines[0].Requirements, 4)
}

// ---- Timestamp backfill: result startTime (value-pinned) ----

// TestConvert_StartTime_FirstActivity pins the exact per-alert startTime taken
// from firstActivityDateTime (the earliest observed activity for the alert).
func TestConvert_StartTime_FirstActivity(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	// sample alert[0] firstActivityDateTime "2021-01-26T20:31:32.9562661Z"
	// → canonical UTC at millisecond precision.
	got := result.Baselines[0].Requirements[0].Results[0].StartTime
	assert.Equal(t, "2021-01-26T20:31:32.956Z", got.Format(time.RFC3339Nano))
}

// TestConvert_StartTime_CreatedFallback pins the createdDateTime fallback branch:
// a present-but-unparseable firstActivityDateTime must not skip a valid
// createdDateTime in favor of the conversion time (mirrors the TS converter).
func TestConvert_StartTime_CreatedFallback(t *testing.T) {
	doc := `{"value":[{"id":"a","status":"new","severity":"low","category":"Execution",` +
		`"title":"t","description":"d","firstActivityDateTime":"not-a-date",` +
		`"createdDateTime":"2024-03-04T05:06:07Z"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	got := result.Baselines[0].Requirements[0].Results[0].StartTime
	assert.Equal(t, "2024-03-04T05:06:07Z", got.Format(time.RFC3339Nano))
}

// ---- Timestamp backfill: top-level timestamp (value-pinned) ----

// TestConvert_TopLevelTimestamp_FromLatestAlert pins the top-level timestamp to
// the latest lastUpdateDateTime across alerts (alert[3] in sample.json).
func TestConvert_TopLevelTimestamp_FromLatestAlert(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2021-01-29T14:30:00Z", result.Timestamp.Format(time.RFC3339Nano))
}

// TestConvert_TopLevelTimestamp_LastActivityFallback pins the per-alert fallback
// from lastUpdateDateTime to lastActivityDateTime.
func TestConvert_TopLevelTimestamp_LastActivityFallback(t *testing.T) {
	doc := `{"value":[{"id":"a","status":"new","severity":"low","category":"Execution",` +
		`"title":"t","description":"d","lastActivityDateTime":"2023-05-06T07:08:09Z"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2023-05-06T07:08:09Z", result.Timestamp.Format(time.RFC3339Nano))
}

// TestConvert_TopLevelTimestamp_CreatedFallback pins the per-alert fallback from
// lastActivityDateTime to createdDateTime.
func TestConvert_TopLevelTimestamp_CreatedFallback(t *testing.T) {
	doc := `{"value":[{"id":"a","status":"new","severity":"low","category":"Execution",` +
		`"title":"t","description":"d","createdDateTime":"2022-02-03T04:05:06Z"}]}`
	result, err := ConvertMsftDefenderEndpointToHDF([]byte(doc), testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2022-02-03T04:05:06Z", result.Timestamp.Format(time.RFC3339Nano))
}

// TestConvert_TopLevelTimestamp_FallsBackToNow confirms the conversion time is
// used only when no alert carries a parseable time (empty tenant window).
func TestConvert_TopLevelTimestamp_FallsBackToNow(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	input := loadFixture(t, "input/empty.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Timestamp)
	assert.False(t, result.Timestamp.Before(before), "empty input should fall back to the conversion time")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-defender-endpoint-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftDefenderEndpointToHDF(input, "1.0.0")
	})
}

// Ground-truth anchor: one requirement per value[] alert, counted independently
// of the converter (shared/go/anchor.go). Each Graph Security API alert maps to
// exactly one requirement — no grouping — so the source count is the length of
// the value[] array. "value" is the sole array under that key at any depth in
// this format, so CountJSONItemsUnderKey is unambiguous. Guards against silent
// under-extraction that TS/Go golden parity cannot detect.
func TestConvert_AlertAnchor(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "value"),
		"sample.json: one requirement per value[] alert")
}

func TestConvert_ControlType(t *testing.T) {
	input := loadFixture(t, "input/sample.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Every alert resolves via the static default NIST tags (SA-11, RA-5)
	// which classify as "management". Each requirement should carry the
	// same controlType.
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

func TestConvertMsftDefenderEndpoint_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftDefenderEndpointToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: MDE alerts come from automated EDR detection", req.ID)
	}
}
