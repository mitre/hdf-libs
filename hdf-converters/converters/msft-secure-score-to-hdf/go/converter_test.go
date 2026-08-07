package msftsecurescore

import (
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
		ConverterName:  "msft-secure-score-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertMsftSecureScoreToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvertMsftSecureScore_MissingSecureScore(t *testing.T) {
	_, err := ConvertMsftSecureScoreToHDF([]byte(`{"profiles": {"value": []}}`), testVersion)
	assert.Error(t, err)
}

func TestConvertMsftSecureScore_MissingProfiles(t *testing.T) {
	_, err := ConvertMsftSecureScoreToHDF([]byte(`{"secureScore": {"value": []}}`), testVersion)
	assert.Error(t, err)
}

// ---- Minimal fixture: baseline structure ----

func TestConvertMsftSecureScore_Minimal(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	// Minimal fixture has 1 secureScore entry → 1 baseline
	require.Len(t, result.Baselines, 1)
	// Minimal fixture has 3 controlScores
	assert.Len(t, result.Baselines[0].Requirements, 3)
}

func TestConvertMsftSecureScore_BaselineName(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Equal(t, "Microsoft Secure Score", result.Baselines[0].Name)
}

func TestConvertMsftSecureScore_BaselineTitle(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Contains(t, *result.Baselines[0].Title, "12345678-1234-1234-1234-1234567890abcd")
}

func TestConvertMsftSecureScore_Checksum(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Baselines[0].ResultsChecksum)
	assert.Equal(t, hdf.Sha256, result.Baselines[0].ResultsChecksum.Algorithm)
	assert.NotEmpty(t, result.Baselines[0].ResultsChecksum.Value)
}

// ---- Generator ----

func TestConvertMsftSecureScore_Generator(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "msft-secure-score-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
}

// ---- Tool ----

func TestConvertMsftSecureScore_Tool(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Name)
	assert.Equal(t, "Microsoft Secure Score", *result.Tool.Name)
	assert.Nil(t, result.Tool.Format, "serialization structures are not formats (kpvj)")
}

// ---- Target ----

func TestConvertMsftSecureScore_Target(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	require.NotEmpty(t, result.Components)
	assert.Equal(t, hdf.CloudAccount, result.Components[0].Type)
	assert.Contains(t, result.Components[0].Name, "12345678-1234-1234-1234-1234567890abcd")
}

// ---- Requirement ID format ----

func TestConvertMsftSecureScore_RequirementID(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// IDs should be "controlCategory:controlName" format
	shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
}

// ---- Requirement title from profile ----

func TestConvertMsftSecureScore_RequirementTitleFromProfile(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has a matching profile with title
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "Deploy a log collector")
}

func TestConvertMsftSecureScore_RequirementTitleFallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// spo_idle_session_timeout has no matching profile → fallback title
	req := shared.MustFindRequirement(t, reqs, "Apps:spo_idle_session_timeout")
	require.NotNil(t, req.Title)
	assert.Contains(t, *req.Title, "spo_idle_session_timeout")
}

// ---- Impact from profile maxScore ----

func TestConvertMsftSecureScore_ImpactFromMaxScore(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has profile.maxScore=1 → impact = 1/10 = 0.1
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	assert.InDelta(t, 0.1, req.Impact, 0.001)

	// dlp_datalossprevention has profile.maxScore=5 → impact = 5/10 = 0.5
	req2 := shared.MustFindRequirement(t, reqs, "Data:dlp_datalossprevention")
	assert.InDelta(t, 0.5, req2.Impact, 0.001)
}

func TestConvertMsftSecureScore_ImpactFallback(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// spo_idle_session_timeout has no profile → default 0.5
	req := shared.MustFindRequirement(t, reqs, "Apps:spo_idle_session_timeout")
	assert.InDelta(t, 0.5, req.Impact, 0.001)
}

// ---- Status mapping ----

func TestConvertMsftSecureScore_StatusPassed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// dlp_datalossprevention has scoreInPercentage=100 → Passed
	req := shared.MustFindRequirement(t, reqs, "Data:dlp_datalossprevention")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
}

func TestConvertMsftSecureScore_StatusFailed(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload has scoreInPercentage=0, score=0, profile.maxScore=1 → Failed
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
}

// ---- CodeDesc from implementationStatus ----

func TestConvertMsftSecureScore_CodeDesc(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	require.NotEmpty(t, req.Results)
	assert.Contains(t, req.Results[0].CodeDesc, "Feature in place: false")
}

// ---- Default description (HTML stripped) ----

func TestConvertMsftSecureScore_Description(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")

	desc := findDescription(req.Descriptions, "default")
	require.NotNil(t, desc, "expected a 'default' description")
	assert.Contains(t, desc.Data, "Log collectors")
}

// ---- Fix description from profile remediation ----

func TestConvertMsftSecureScore_FixDescription(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")

	fix := findDescription(req.Descriptions, "fix")
	require.NotNil(t, fix, "expected a 'fix' description")
	assert.NotEmpty(t, fix.Data)
}

// ---- Refs from profile actionUrl ----

func TestConvertMsftSecureScore_RefsFromActionURL(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// McasFirewallLogUpload profile carries actionUrl → one Reference{URL}.
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	require.Len(t, req.Refs, 1)
	require.NotNil(t, req.Refs[0].URL)
	assert.Equal(t, "https://security.microsoft.com/cloudapps/settings?tabid=discovery-autoUpload", *req.Refs[0].URL)

	// dlp_datalossprevention profile carries a different actionUrl.
	req2 := shared.MustFindRequirement(t, reqs, "Data:dlp_datalossprevention")
	require.Len(t, req2.Refs, 1)
	require.NotNil(t, req2.Refs[0].URL)
	assert.Equal(t, "https://compliance.microsoft.com/datalossprevention?tid=12345678-1234-1234-1234-1234567890abcd", *req2.Refs[0].URL)
}

func TestConvertMsftSecureScore_RefsAbsentWhenNoProfile(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements

	// spo_idle_session_timeout has no matching profile → refs omitted.
	req := shared.MustFindRequirement(t, reqs, "Apps:spo_idle_session_timeout")
	assert.Empty(t, req.Refs)
}

// ---- NIST tags (static analysis defaults) ----

func TestConvertMsftSecureScore_NistTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")

	nist := hdfutil.SafeStringSlice(req.Tags["nist"])
	require.NotNil(t, nist, "nist tag should be present")
	assert.NotEmpty(t, nist)
}

// ---- StartTime (value-pinned to control lastSynced) ----

func TestConvertMsftSecureScore_StartTime(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	// McasFirewallLogUpload carries lastSynced "2024-01-01T04:34:13Z" — startTime
	// must be that control's own sync time, NOT the score's createdDateTime.
	req := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, "2024-01-01T04:34:13Z", req.Results[0].StartTime.UTC().Format(time.RFC3339))

	// A different control has a distinct lastSynced — proves per-control mapping.
	dlp := shared.MustFindRequirement(t, reqs, "Data:dlp_datalossprevention")
	require.NotEmpty(t, dlp.Results)
	assert.Equal(t, "2024-01-01T13:58:47Z", dlp.Results[0].StartTime.UTC().Format(time.RFC3339))
}

// StartTime fallback: a control missing lastSynced falls back to the score's
// createdDateTime (never zero/empty — startTime is schema-required).
func TestConvertMsftSecureScore_StartTimeFallback(t *testing.T) {
	input := []byte(`{
		"secureScore": {"value": [{
			"id": "run-1",
			"azureTenantId": "t-1",
			"createdDateTime": "2024-03-14T09:00:00Z",
			"controlScores": [
				{"controlCategory": "Apps", "controlName": "no_sync", "description": "d", "score": 0, "implementationStatus": "x", "scoreInPercentage": 0}
			]
		}]},
		"profiles": {"value": []}
	}`)
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	req := shared.MustFindRequirement(t, result.Baselines[0].Requirements, "Apps:no_sync")
	require.NotEmpty(t, req.Results)
	assert.Equal(t, "2024-03-14T09:00:00Z", req.Results[0].StartTime.UTC().Format(time.RFC3339),
		"missing lastSynced should fall back to createdDateTime")
}

// ---- Full fixture smoke test ----

func TestConvertMsftSecureScore_FullFixture(t *testing.T) {
	input := loadFixture(t, "input/combined.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	// Full fixture has 1 secureScore entry with 68 controlScores
	require.Len(t, result.Baselines, 1)
	assert.Len(t, result.Baselines[0].Requirements, 68)

	// Each requirement should have exactly 1 result
	for _, req := range result.Baselines[0].Requirements {
		assert.Len(t, req.Results, 1, "requirement %s should have exactly 1 result", req.ID)
	}
}

// ---- Timestamp ----

func TestConvertMsftSecureScore_Timestamp(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	// Top-level timestamp is source-derived from the score's createdDateTime,
	// not wall-clock now — this is what makes conversion deterministic.
	require.NotNil(t, result.Timestamp)
	assert.Equal(t, "2024-01-01T00:00:00Z", result.Timestamp.UTC().Format(time.RFC3339))
}

// ---- Source categorization/metadata tags ----

func TestConvertMsftSecureScore_SourceMetadataTags(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// dlp_datalossprevention: full profile metadata; threats is [] → omitted; on == "true".
	dlp := shared.MustFindRequirement(t, reqs, "Data:dlp_datalossprevention")
	assert.EqualValues(t, 128, dlp.Tags["rank"])
	assert.Equal(t, "MIP", dlp.Tags["service"])
	assert.Equal(t, "Core", dlp.Tags["tier"])
	assert.Equal(t, "High", dlp.Tags["user_impact"])
	assert.Equal(t, "Config", dlp.Tags["action_type"])
	assert.Equal(t, "Medium", dlp.Tags["implementation_cost"])
	assert.Equal(t, true, dlp.Tags["on"])
	_, hasThreats := dlp.Tags["threats"]
	assert.False(t, hasThreats, "empty threats array should be omitted")

	// McasFirewallLogUpload: non-empty threats array; on == "false".
	mcas := shared.MustFindRequirement(t, reqs, "Apps:McasFirewallLogUpload")
	assert.Equal(t, []interface{}{"Data Exfiltration"}, mcas.Tags["threats"])
	assert.EqualValues(t, 82, mcas.Tags["rank"])
	assert.Equal(t, "MCAS", mcas.Tags["service"])
	assert.Equal(t, "Advanced", mcas.Tags["tier"])
	assert.Equal(t, "Low", mcas.Tags["user_impact"])
	assert.Equal(t, "Config", mcas.Tags["action_type"])
	assert.Equal(t, "Moderate", mcas.Tags["implementation_cost"])
	assert.Equal(t, false, mcas.Tags["on"])
}

func TestConvertMsftSecureScore_SourceMetadataTagsAbsentWhenNoProfile(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// spo_idle_session_timeout has no matching profile → no profile-derived tags,
	// but `on` is still emitted from the control score itself ("false").
	req := shared.MustFindRequirement(t, reqs, "Apps:spo_idle_session_timeout")
	for _, k := range []string{"threats", "rank", "service", "tier", "user_impact", "action_type", "implementation_cost"} {
		_, ok := req.Tags[k]
		assert.Falsef(t, ok, "tag %q should be absent when no profile matches", k)
	}
	assert.Equal(t, false, req.Tags["on"])
}

func TestConvertMsftSecureScore_OnTagOmittedWhenNull(t *testing.T) {
	input := loadFixture(t, "input/combined.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	var sawPresent, sawOmitted bool
	for _, req := range result.Baselines[0].Requirements {
		if _, ok := req.Tags["on"]; ok {
			sawPresent = true
		} else {
			sawOmitted = true
		}
	}
	assert.True(t, sawPresent, "controls with a true/false on flag emit the tag")
	assert.True(t, sawOmitted, "controls with null/absent on omit the tag")
}

func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "msft-secure-score-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertMsftSecureScoreToHDF(input, "1.0.0")
	})
}

// Ground-truth anchor: one requirement per secureScore.value[].controlScores[]
// entry, summed across all secureScore entries, counted independently of the
// converter (shared/go/anchor.go). Each control score becomes exactly one
// requirement — no grouping. "controlScores" is the sole array under that key at
// any depth in this format, so CountJSONItemsUnderKey is unambiguous (unlike
// "value", which appears under both secureScore and profiles). Guards against
// silent under-extraction that TS/Go golden parity cannot detect.
func TestConvert_ControlScoreAnchor(t *testing.T) {
	input := loadFixture(t, "input/combined.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertRequirementCount(t, result, shared.CountJSONItemsUnderKey(t, input, "controlScores"),
		"combined.json: one requirement per secureScore.value[].controlScores[] entry")
}

func TestConvertMsftSecureScore_ControlType(t *testing.T) {
	input := loadFixture(t, "input/combined.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)

	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)

	// Every control uses the static default NIST tags (SA-11, RA-5) which
	// classify as "management". Each requirement should carry the controlType.
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

func TestConvertMsftSecureScore_VerificationMethod(t *testing.T) {
	input := loadFixture(t, "input/minimal.json")
	result, err := ConvertMsftSecureScoreToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotEmpty(t, result.Baselines)
	reqs := result.Baselines[0].Requirements
	require.NotEmpty(t, reqs)
	for _, req := range reqs {
		require.NotNil(t, req.VerificationMethod, "requirement %q missing verificationMethod", req.ID)
		assert.Equal(t, hdf.VerificationMethodEnumAutomated, *req.VerificationMethod,
			"requirement %q: Secure Score controls are evaluated automatically by Microsoft Graph", req.ID)
	}
}
