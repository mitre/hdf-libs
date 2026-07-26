package hipcheck

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
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

func findReq(reqs []hdf.EvaluatedRequirement, id string) *hdf.EvaluatedRequirement {
	for i := range reqs {
		if reqs[i].ID == id {
			return &reqs[i]
		}
	}
	return nil
}

func nistTags(t *testing.T, req *hdf.EvaluatedRequirement) []string {
	t.Helper()
	require.NotNil(t, req)
	return shared.NISTTagsFromMap(req.Tags)
}

// ---- Contract ----

func TestConverterContract(t *testing.T) {
	shared.RunConverterContractTests(t, shared.ConverterContractSpec{
		ConverterName:  "hipcheck-to-hdf",
		ConvertFn:      func(input []byte) (interface{}, error) { return ConvertHipcheckToHDF(input, testVersion) },
		MinimalFixture: "minimal.json",
	})
}

func TestConvert_NotAHipcheckReport(t *testing.T) {
	_, err := ConvertHipcheckToHDF([]byte(`{"foo":1}`), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not look like a Hipcheck report")
}

// ---- Real fixture (juice-shop, Investigate) ----

func TestConvert_Real_Structure(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/real.json"), testVersion)
	require.NoError(t, err)

	require.Len(t, result.Baselines, 1)
	bl := result.Baselines[0]
	assert.Equal(t, "Hipcheck Scan", bl.Name)
	require.NotNil(t, bl.Title)
	assert.Equal(t, "Hipcheck analysis of juice-shop/juice-shop @ v20.1.1", *bl.Title)

	// 3 passing + 3 failing + 2 errored
	assert.Len(t, bl.Requirements, 8)

	require.NotNil(t, result.Tool)
	require.NotNil(t, result.Tool.Version)
	assert.Equal(t, "3.15.0", *result.Tool.Version)

	require.Len(t, result.Components, 1)
	assert.Equal(t, "juice-shop/juice-shop", result.Components[0].Name)
	assert.Equal(t, hdf.Repository, result.Components[0].Type)
}

func TestConvert_Real_Summary_InvestigateFailedAnalyses(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/real.json"), testVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Baselines[0].Summary)
	assert.Equal(t,
		"Hipcheck recommendation: Investigate (risk score 0.42, policy '(gt 0.5 $)'). Investigation forced by failed analyses: mitre/binary.",
		*result.Baselines[0].Summary)
}

func TestConvert_Real_StatusMapping(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/real.json"), testVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// passing -> passed
	activity := findReq(reqs, "mitre/activity")
	require.NotNil(t, activity)
	assert.Equal(t, hdf.Passed, activity.Results[0].Status)
	assert.Equal(t, 0.5, activity.Impact)

	// failing -> failed, with concerns folded into the message
	binary := findReq(reqs, "mitre/binary")
	require.NotNil(t, binary)
	assert.Equal(t, hdf.Failed, binary.Results[0].Status)
	require.NotNil(t, binary.Results[0].Message)
	assert.Contains(t, *binary.Results[0].Message, "invalidTypeForClient.exe")

	// errored -> error
	review := findReq(reqs, "mitre/review")
	require.NotNil(t, review)
	assert.Equal(t, hdf.Error, review.Results[0].Status)
	require.NotNil(t, review.Results[0].Message)
	assert.Equal(t, "unknown error", *review.Results[0].Message)
}

func TestConvert_Real_NISTTags(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/real.json"), testVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	assert.Equal(t, []string{"SI-7", "SR-4"}, nistTags(t, findReq(reqs, "mitre/binary")))
	assert.Equal(t, []string{"SR-3", "SR-4"}, nistTags(t, findReq(reqs, "mitre/activity")))
	assert.Equal(t, []string{"SA-11"}, nistTags(t, findReq(reqs, "mitre/fuzz")))
	assert.Equal(t, []string{"SA-15"}, nistTags(t, findReq(reqs, "mitre/review")))

	// verificationMethod is a per-converter constant (Hipcheck is an automated analyzer)
	fuzz := findReq(reqs, "mitre/fuzz")
	require.NotNil(t, fuzz.VerificationMethod)
	assert.Equal(t, hdf.VerificationMethodEnumAutomated, *fuzz.VerificationMethod)
}

// ---- Pass fixture (local run, Pass / reason null / binary passing) ----

func TestConvert_Pass_Summary(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/pass.json"), testVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Baselines[0].Summary)
	assert.Equal(t,
		"Hipcheck recommendation: Pass (risk score 0.33, policy '(gt 0.5 $)').",
		*result.Baselines[0].Summary)

	require.NotNil(t, result.Baselines[0].Title)
	assert.Equal(t, "Hipcheck analysis of asff-to-hdf @ feat/aws-config-hdf-enrichment", *result.Baselines[0].Title)

	// binary passes here (unlike juice-shop)
	binary := findReq(result.Baselines[0].Requirements, "mitre/binary")
	require.NotNil(t, binary)
	assert.Equal(t, hdf.Passed, binary.Results[0].Status)

	// owner is null -> component name is the bare repo name
	require.Len(t, result.Components, 1)
	assert.Equal(t, "asff-to-hdf", result.Components[0].Name)
}

// ---- Empty fixture (no analyses -> synthesized placeholder) ----

func TestConvert_Empty_NoFindingsPlaceholder(t *testing.T) {
	result, err := ConvertHipcheckToHDF(loadFixture(t, "input/empty.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)

	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "hipcheck-no-findings", req.ID)
	require.Len(t, req.Results, 1)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Contains(t, req.Results[0].CodeDesc, "Hipcheck")

	require.NotNil(t, result.Baselines[0].Summary)
	assert.Equal(t,
		"Hipcheck recommendation: Pass (risk score 0, policy '(gt 0.5 $)').",
		*result.Baselines[0].Summary)
}

// ---- Recommendation reason variants (unit) ----

func TestBuildSummary_ReasonVariants(t *testing.T) {
	// Pass -> no reason suffix
	assert.Equal(t,
		"Hipcheck recommendation: Pass (risk score 0.1, policy '(gt 0.5 $)').",
		buildSummary(Recommendation{Kind: "Pass", Reason: json.RawMessage("null"), RiskScore: 0.1, RiskPolicy: "(gt 0.5 $)"}))

	// Investigate + "Policy" string variant
	assert.Equal(t,
		"Hipcheck recommendation: Investigate (risk score 0.7, policy '(gt 0.5 $)'). Investigation triggered because the risk score exceeded the policy threshold.",
		buildSummary(Recommendation{Kind: "Investigate", Reason: json.RawMessage(`"Policy"`), RiskScore: 0.7, RiskPolicy: "(gt 0.5 $)"}))

	// Investigate + FailedAnalyses object variant
	assert.Equal(t,
		"Hipcheck recommendation: Investigate (risk score 0.42, policy '(gt 0.5 $)'). Investigation forced by failed analyses: mitre/binary, mitre/typo.",
		buildSummary(Recommendation{Kind: "Investigate", Reason: json.RawMessage(`{"FailedAnalyses":["mitre/binary","mitre/typo"]}`), RiskScore: 0.42, RiskPolicy: "(gt 0.5 $)"}))
}

func TestFlattenError_Chain(t *testing.T) {
	assert.Equal(t, "unknown error", flattenError(&ErrorReport{Msg: "unknown error"}))
	assert.Equal(t, "top: middle: root",
		flattenError(&ErrorReport{Msg: "top", Source: &ErrorReport{Msg: "middle", Source: &ErrorReport{Msg: "root"}}}))
	assert.Equal(t, "unknown error", flattenError(nil))
}

// ---- Schema validation ----

func TestConvert_SchemaValid(t *testing.T) {
	for _, fx := range []string{"input/real.json", "input/pass.json", "input/empty.json", "input/minimal.json"} {
		result, err := ConvertHipcheckToHDF(loadFixture(t, fx), testVersion)
		require.NoError(t, err, fx)
		data, err := json.Marshal(result)
		require.NoError(t, err, fx)
		vr := validators.ValidateResults(data)
		assert.True(t, vr.Valid, "%s must produce schema-valid HDF: %s", fx, vr.Error())
	}
}

// ---- Fingerprint ----

func TestFingerprint(t *testing.T) {
	full := map[string]any{
		"hipcheck_version": "3.15.0",
		"recommendation":   map[string]any{"risk_score": 0.42},
	}
	assert.Equal(t, 1.0, isHipcheckReport(full))

	recNoScore := map[string]any{
		"hipcheck_version": "3.15.0",
		"recommendation":   map[string]any{"kind": "Pass"},
	}
	assert.Equal(t, 0.9, isHipcheckReport(recNoScore))

	versionOnly := map[string]any{"hipcheck_version": "3.15.0"}
	assert.Equal(t, 0.6, isHipcheckReport(versionOnly))

	assert.Equal(t, 0.0, isHipcheckReport(map[string]any{"foo": 1}))
}

// ---- Unknown analysis (no NIST mapping) ----

func TestAnalysisTags_Unknown(t *testing.T) {
	tags, nist := analysisTags("mitre/not-a-real-analysis")
	assert.Nil(t, nist)
	assert.Empty(t, shared.NISTTagsFromMap(tags))
}

// ---- Summary / reason edge branches ----

func TestBuildSummary_InvestigateNullReason(t *testing.T) {
	// Investigate with a null reason yields the base sentence, no suffix.
	assert.Equal(t,
		"Hipcheck recommendation: Investigate (risk score 0.6, policy '(gt 0.5 $)').",
		buildSummary(Recommendation{Kind: "Investigate", Reason: json.RawMessage("null"), RiskScore: 0.6, RiskPolicy: "(gt 0.5 $)"}))
}

func TestInvestigateReason_Variants(t *testing.T) {
	assert.Equal(t, "", investigateReason(json.RawMessage("null")))
	assert.Equal(t, "", investigateReason(json.RawMessage("")))
	assert.Equal(t,
		"Investigation triggered because the risk score exceeded the policy threshold.",
		investigateReason(json.RawMessage(`"Policy"`)))
	assert.Equal(t, "Investigation reason: Other.", investigateReason(json.RawMessage(`"Other"`)))
	// object with empty list -> no sentence
	assert.Equal(t, "", investigateReason(json.RawMessage(`{"FailedAnalyses":[]}`)))
}

func TestRepoIdent_Variants(t *testing.T) {
	owner := "acme"
	empty := ""
	assert.Equal(t, "acme/widget", repoIdent(Report{RepoOwner: &owner, RepoName: "widget"}))
	assert.Equal(t, "widget", repoIdent(Report{RepoOwner: nil, RepoName: "widget"}))
	// owner present but no name must NOT yield a trailing-slash "acme/"
	assert.Equal(t, "acme", repoIdent(Report{RepoOwner: &owner, RepoName: ""}))
	assert.Equal(t, "widget", repoIdent(Report{RepoOwner: &empty, RepoName: "widget"}))
	assert.Equal(t, "", repoIdent(Report{RepoOwner: nil, RepoName: ""}))
}

func TestFlattenError_EmptyMsg(t *testing.T) {
	assert.Equal(t, "unknown error", flattenError(&ErrorReport{}))
}

// ---- Timestamp fallback ----

func TestConvert_UnparseableTimestampFallsBack(t *testing.T) {
	input := []byte(`{"repo_name":"x","hipcheck_version":"3.15.0","analyzed_at":"","passing":[],"failing":[],"errored":[],"recommendation":{"kind":"Pass","reason":null,"risk_score":0,"risk_policy":"(gt 0.5 $)"}}`)
	result, err := ConvertHipcheckToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines[0].Requirements, 1)
	assert.False(t, result.Baselines[0].Requirements[0].Results[0].StartTime.IsZero())
}

// ---- Snapshot (whole-output golden; Go<->TS parity) ----

func TestSnapshot(t *testing.T) {
	shared.RunSnapshotTests(t, "hipcheck-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertHipcheckToHDF(input, "1.0.0")
	})
}
