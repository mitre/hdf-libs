package defectdojo_to_hdf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const converterVersion = "0.1.0"

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	p := filepath.Join(shared.GetConvertersDir(), "defectdojo-to-hdf", "fixtures", "input", name)
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	return data
}

// requirementByTriage finds the single requirement whose triage tag is set true.
func requirementByTriage(t *testing.T, reqs []hdf.EvaluatedRequirement, tag string) hdf.EvaluatedRequirement {
	t.Helper()
	for _, r := range reqs {
		if v, ok := r.Tags[tag].(bool); ok && v {
			return r
		}
	}
	t.Fatalf("no requirement with %s=true", tag)
	return hdf.EvaluatedRequirement{}
}

func TestConvertDefectDojo_Findings(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	require.NotNil(t, result.Generator)
	assert.Equal(t, "defectdojo-to-hdf", result.Generator.Name)

	// All four sample findings came from the "Generic Findings Import" test_type
	// → a single per-scanner baseline.
	require.Len(t, result.Baselines, 1)
	base := result.Baselines[0]
	assert.Equal(t, "DefectDojo: Generic Findings Import", base.Name)
	require.Len(t, base.Requirements, 4)

	// Output must be schema-valid.
	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(out).Valid, "HDF output must validate: %s", validators.ValidateResults(out).Error())
}

func TestConvertDefectDojo_StatusMapping(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	// active (untriaged) → failed
	active := requirementByTriage(t, reqs, "defectdojo/active")
	assert.Equal(t, hdf.Failed, active.Results[0].Status)

	// false_p → raw stays failed; the dismissal rides in a falsePositive override
	// (effectiveStatus notApplicable), not a rewrite of the raw status.
	fp := requirementByTriage(t, reqs, "defectdojo/false_p")
	assert.Equal(t, hdf.Failed, fp.Results[0].Status)
	require.NotNil(t, fp.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *fp.EffectiveStatus)

	// is_mitigated → passed (only when it is not also false_p/risk_accepted)
	// finding 3 in the fixture is mitigated-only.
	var mitigatedOnly *hdf.EvaluatedRequirement
	for i := range reqs {
		r := reqs[i]
		if b, _ := r.Tags["defectdojo/is_mitigated"].(bool); b {
			if fp2, _ := r.Tags["defectdojo/false_p"].(bool); !fp2 {
				mitigatedOnly = &reqs[i]
			}
		}
	}
	require.NotNil(t, mitigatedOnly, "expected a mitigated-only requirement")
	assert.Equal(t, hdf.Passed, mitigatedOnly.Results[0].Status)
}

func TestConvertDefectDojo_RiskAcceptanceWaiverOverride(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	ra := requirementByTriage(t, reqs, "defectdojo/risk_accepted")

	// Raw status stays failed; the acceptance is an override, not a rewrite.
	assert.Equal(t, hdf.Failed, ra.Results[0].Status)

	// Effective axis reflects the waiver, fully attributed.
	require.NotNil(t, ra.EffectiveStatus)
	assert.Equal(t, hdf.Passed, *ra.EffectiveStatus)
	require.NotNil(t, ra.Disposition)
	assert.Equal(t, hdf.OverrideTypeWaiver, *ra.Disposition)

	require.Len(t, ra.StatusOverrides, 1)
	ov := ra.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.Passed, *ov.Status)
	assert.Contains(t, ov.Reason, "WAF virtual patch") // real decision_details, not fabricated
	assert.Equal(t, "defectdojo-user-1", ov.AppliedBy.Identifier)
	assert.Equal(t, hdf.Simple, ov.AppliedBy.Type)
	assert.Equal(t, 2099, ov.ExpiresAt.Year()) // real expiration_date
	assert.False(t, ov.AppliedAt.IsZero())
}

// TestConvertDefectDojo_FalsePositiveOverride pins the falsePositive override
// reconstructed from a DefectDojo false-positive dismissal (finding 2 in the
// fixture: false_p=true, mitigated_by=1, mitigated=2026-07-26). Raw status stays
// failed; effectiveStatus becomes notApplicable (a vuln aggregator's FP means the
// vuln does not apply), fully attributed to the reviewer.
func TestConvertDefectDojo_FalsePositiveOverride(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	fp := requirementByTriage(t, reqs, "defectdojo/false_p")

	// Raw status stays failed; the dismissal is an override, not a rewrite.
	assert.Equal(t, hdf.Failed, fp.Results[0].Status)

	require.NotNil(t, fp.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *fp.EffectiveStatus)
	require.NotNil(t, fp.Disposition)
	assert.Equal(t, hdf.FalsePositive, *fp.Disposition)

	require.Len(t, fp.StatusOverrides, 1)
	ov := fp.StatusOverrides[0]
	assert.Equal(t, hdf.FalsePositive, ov.Type)
	require.NotNil(t, ov.Status)
	assert.Equal(t, hdf.NotApplicable, *ov.Status)
	assert.Equal(t, "Some mitigation", ov.Reason) // the finding's mitigation note
	assert.Equal(t, "defectdojo-user-1", ov.AppliedBy.Identifier)
	assert.Equal(t, hdf.Simple, ov.AppliedBy.Type)
	assert.Equal(t, 2026, ov.AppliedAt.Year()) // mitigated date
	assert.Equal(t, 2027, ov.ExpiresAt.Year()) // appliedAt + 1yr
	assert.Equal(t, ov.AppliedAt.AddDate(1, 0, 0), ov.ExpiresAt)
}

// TestConvertDefectDojo_NoOverrideForUntriaged locks the no-triage branch: the
// active, untriaged finding (finding 1) carries no override — raw status
// unchanged, no effectiveStatus/disposition/statusOverrides.
func TestConvertDefectDojo_NoOverrideForUntriaged(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	active := requirementByTriage(t, result.Baselines[0].Requirements, "defectdojo/active")

	assert.Equal(t, hdf.Failed, active.Results[0].Status)
	assert.Nil(t, active.EffectiveStatus, "untriaged finding carries no effectiveStatus")
	assert.Nil(t, active.Disposition, "untriaged finding carries no disposition")
	assert.Empty(t, active.StatusOverrides, "untriaged finding carries no override")
}

// TestBuildFalsePositiveOverride_Branches covers the falsePositive builder's
// reviewer-identity precedence, reason fallback, and appliedAt fallbacks.
func TestBuildFalsePositiveOverride_Branches(t *testing.T) {
	email := "rev@example.com"
	user := "reviewer"

	// email > username > user id > system identity precedence
	assert.Equal(t, hdf.Identity{Type: hdf.Email, Identifier: email},
		buildFalsePositiveOverride(ddFinding{MitigatedByEmail: &email, MitigatedByUsername: &user, MitigatedBy: "1"}).AppliedBy)
	assert.Equal(t, hdf.Identity{Type: hdf.Username, Identifier: user},
		buildFalsePositiveOverride(ddFinding{MitigatedByUsername: &user, MitigatedBy: "1"}).AppliedBy)
	assert.Equal(t, hdf.Identity{Type: hdf.Simple, Identifier: "defectdojo-user-7"},
		buildFalsePositiveOverride(ddFinding{MitigatedBy: "7"}).AppliedBy)
	assert.Equal(t, hdf.Identity{Type: hdf.IdentityTypeOther, Identifier: "defectdojo (false positive triage)"},
		buildFalsePositiveOverride(ddFinding{}).AppliedBy)

	// reason: mitigation note when present, else constant fallback
	assert.Equal(t, "note here", buildFalsePositiveOverride(ddFinding{Mitigation: "note here"}).Reason)
	assert.Equal(t, "Marked as false positive in DefectDojo", buildFalsePositiveOverride(ddFinding{}).Reason)

	// appliedAt: mitigated date wins; else finding date; expiresAt is +1yr
	mit := "2030-05-01T00:00:00Z"
	ovMit := buildFalsePositiveOverride(ddFinding{Mitigated: &mit, Date: "2020-01-01"})
	assert.Equal(t, 2030, ovMit.AppliedAt.Year())
	assert.Equal(t, 2031, ovMit.ExpiresAt.Year())

	ovDate := buildFalsePositiveOverride(ddFinding{Date: "2022-03-04"})
	assert.Equal(t, "2022-03-04T00:00:00Z", ovDate.AppliedAt.UTC().Format(time.RFC3339))

	// no mitigated date and no finding date → now() fallback (non-zero)
	ovNow := buildFalsePositiveOverride(ddFinding{})
	assert.False(t, ovNow.AppliedAt.IsZero())
}

// TestConvertFinding_WaiverWinsOverFalsePositive locks the documented precedence:
// a finding that is both risk-accepted and false-positive gets the waiver, not
// the falsePositive override.
func TestConvertFinding_WaiverWinsOverFalsePositive(t *testing.T) {
	req := convertFinding(ddFinding{
		Title:         "t",
		Severity:      "High",
		FalseP:        true,
		RiskAccepted:  true,
		AcceptedRisks: []ddAcceptedRisk{{Name: "AcceptName"}},
	})
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.OverrideTypeWaiver, *req.Disposition)
	require.Len(t, req.StatusOverrides, 1)
	assert.Equal(t, hdf.OverrideTypeWaiver, req.StatusOverrides[0].Type)
}

// TestConvertDefectDojo_RequirementCode pins requirement.code to the raw
// DefectDojo finding serialized as indented JSON (the Heimdall CODE tab source).
// No golden fixture exists, so this asserts each code round-trips to its source
// finding object and is indented — the value-pinning contract.
func TestConvertDefectDojo_RequirementCode(t *testing.T) {
	input := loadFixture(t, "findings.json")
	result, err := ConvertDefectDojo(input, converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements
	require.Len(t, reqs, 4)

	var env struct {
		Results []json.RawMessage `json:"results"`
	}
	require.NoError(t, json.Unmarshal(input, &env))
	require.Len(t, env.Results, 4)

	for i, req := range reqs {
		require.NotNil(t, req.Code, "requirement %d must carry code", i)
		assert.Contains(t, *req.Code, "\n  ", "code must be indented")
		var got, want map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(*req.Code), &got))
		require.NoError(t, json.Unmarshal(env.Results[i], &want))
		assert.Equal(t, want, got, "code must round-trip to the source finding")
	}
}

// TestBuildFindingCode_Branches covers every branch of buildFindingCode: the
// no-raw-bytes guard, the malformed-raw guard, and the indented success path.
func TestBuildFindingCode_Branches(t *testing.T) {
	// no raw bytes (a synthesized finding, not parsed from source) → unset
	assert.Equal(t, "", buildFindingCode(ddFinding{}))
	// malformed raw bytes → unset (defensive; unreachable via UnmarshalJSON)
	assert.Equal(t, "", buildFindingCode(ddFinding{raw: json.RawMessage("{not json")}))
	// valid raw → indented, round-trips
	code := buildFindingCode(ddFinding{raw: json.RawMessage(`{"id":1,"title":"x"}`)})
	assert.Contains(t, code, "\n  \"id\": 1")
	var got map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(code), &got))
	assert.Equal(t, map[string]interface{}{"id": float64(1), "title": "x"}, got)
}

// TestConvertFinding_NoCodeWithoutRaw covers the caller branch that leaves code
// unset when the finding carries no raw bytes.
func TestConvertFinding_NoCodeWithoutRaw(t *testing.T) {
	req := convertFinding(ddFinding{Title: "t", Severity: "High"})
	assert.Nil(t, req.Code, "code must be unset when no raw source bytes are present")
}

// TestConvertDefectDojo_CVETag pins the CVE from vulnerability_ids[] into
// tags.cve. The requirement.id is a native DefectDojo finding id
// (DefectDojo-Finding-<n>), never the CVE, so tags.cve is not a duplicate of it.
func TestConvertDefectDojo_CVETag(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	reqs := result.Baselines[0].Requirements

	byID := map[string]hdf.EvaluatedRequirement{}
	for _, r := range reqs {
		byID[r.ID] = r
	}

	first, ok := byID["DefectDojo-Finding-1"]
	require.True(t, ok, "id must be the native finding id, not the CVE")
	assert.Equal(t, []string{"CVE-2020-36234"}, first.Tags["cve"])
	assert.Equal(t, []string{"CVE-2020-36235"}, byID["DefectDojo-Finding-2"].Tags["cve"])
	assert.Equal(t, []string{"CVE-2020-36236"}, byID["DefectDojo-Finding-3"].Tags["cve"])
	assert.Equal(t, []string{"CVE-2020-36236"}, byID["DefectDojo-Finding-4"].Tags["cve"])
}

// TestBuildCVETag_Branches covers the multi-CVE (empty ids dropped) and
// absent-CVE branches of the tags.cve mapping.
func TestBuildCVETag_Branches(t *testing.T) {
	multi := convertFinding(ddFinding{
		Title:    "t",
		Severity: "High",
		VulnerabilityIDs: []ddVulnID{
			{VulnerabilityID: "CVE-2021-1"},
			{VulnerabilityID: ""},
			{VulnerabilityID: "CVE-2021-2"},
		},
	})
	assert.Equal(t, []string{"CVE-2021-1", "CVE-2021-2"}, multi.Tags["cve"])

	none := convertFinding(ddFinding{Title: "t", Severity: "High"})
	_, present := none.Tags["cve"]
	assert.False(t, present, "no vulnerability_ids → tags.cve absent")
}

// TestConvertDefectDojo_NoKev locks the KEV NOT-IN-SOURCE decision: DefectDojo
// carries no CISA remediation due date, so requirement.kev (which requires
// dateAdded + dueDate when inKev=true) is never emitted.
func TestConvertDefectDojo_NoKev(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	for _, r := range result.Baselines[0].Requirements {
		assert.Nil(t, r.Kev, "defectdojo never emits requirement.kev (no source due date)")
	}
}

// TestConvertDefectDojo_TopLevelTimestamp pins the top-level HDF timestamp to the
// newest finding `date` in the fixture (finding 4, "2024-01-04"). The shared
// snapshot masks timestamp values, so this asserts the exact source-derived value.
func TestConvertDefectDojo_TopLevelTimestamp(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	require.NotNil(t, result.Timestamp, "top-level timestamp must be populated from source")

	out, err := json.Marshal(result)
	require.NoError(t, err)
	var doc struct {
		Timestamp string `json:"timestamp"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, "2024-01-04T00:00:00Z", doc.Timestamp)
}

// TestConvertDefectDojo_StartTimeSourceDerived pins result startTime to the
// finding `date` (date-only, promoted to UTC midnight) — proving Go parses the
// bare date rather than dropping it to now(), matching the TS twin.
func TestConvertDefectDojo_StartTimeSourceDerived(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	byID := map[string]hdf.EvaluatedRequirement{}
	for _, r := range result.Baselines[0].Requirements {
		byID[r.ID] = r
	}
	assert.Equal(t, "2021-01-06T00:00:00Z", byID["DefectDojo-Finding-1"].Results[0].StartTime.UTC().Format(time.RFC3339))
	assert.Equal(t, "2024-01-04T00:00:00Z", byID["DefectDojo-Finding-4"].Results[0].StartTime.UTC().Format(time.RFC3339))
}

// TestConvertDefectDojo_Deterministic proves the mapped timestamps are
// source-anchored, not wall-clock: converting the fixture twice yields
// byte-identical output (every finding carries a date, so no now() fallback runs).
func TestConvertDefectDojo_Deterministic(t *testing.T) {
	input := loadFixture(t, "findings.json")
	first, err := ConvertDefectDojo(input, converterVersion)
	require.NoError(t, err)
	second, err := ConvertDefectDojo(input, converterVersion)
	require.NoError(t, err)
	a, err := json.Marshal(first)
	require.NoError(t, err)
	b, err := json.Marshal(second)
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b), "conversion must be deterministic (no wall-clock timestamps)")
}

// TestConvertDefectDojo_TimestampOmittedWhenNoDate covers the fallback branch: a
// findings array carrying no parseable date omits the optional top-level timestamp
// rather than fabricating a wall-clock value.
func TestConvertDefectDojo_TimestampOmittedWhenNoDate(t *testing.T) {
	result, err := ConvertDefectDojo([]byte(`[{"id":1,"title":"t","severity":"High"}]`), converterVersion)
	require.NoError(t, err)
	assert.Nil(t, result.Timestamp, "no source date → top-level timestamp omitted")
}

// TestParseFindingDate_Branches covers every branch of parseFindingDate and
// latestFindingDate: date-only promotion, full RFC3339 passthrough, unparseable,
// and the latest-of-many selection with zero values skipped.
func TestParseFindingDate_Branches(t *testing.T) {
	assert.Equal(t, "2024-01-04T00:00:00Z", parseFindingDate("2024-01-04").UTC().Format(time.RFC3339))
	assert.Equal(t, "2024-01-04T10:30:00Z", parseFindingDate("2024-01-04T10:30:00Z").UTC().Format(time.RFC3339))
	assert.True(t, parseFindingDate("").IsZero())
	assert.True(t, parseFindingDate("not-a-date").IsZero())

	assert.True(t, latestFindingDate(nil).IsZero())
	assert.True(t, latestFindingDate([]ddFinding{{Date: "nope"}}).IsZero())
	latest := latestFindingDate([]ddFinding{{Date: "2021-01-06"}, {Date: ""}, {Date: "2024-01-04"}})
	assert.Equal(t, "2024-01-04T00:00:00Z", latest.UTC().Format(time.RFC3339))
}

// TestConvertDefectDojo_SourceLocation pins the structured requirement.sourceLocation
// promoted from the finding's file_path/line. The shared value-pin: finding 1 →
// src/first.cpp:13, finding 2 → src/two.cpp:135. Line serializes as a plain number
// (float64 without fraction) so Go and TS stay byte-identical.
func TestConvertDefectDojo_SourceLocation(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "findings.json"), converterVersion)
	require.NoError(t, err)
	byID := map[string]hdf.EvaluatedRequirement{}
	for _, r := range result.Baselines[0].Requirements {
		byID[r.ID] = r
	}

	first := byID["DefectDojo-Finding-1"]
	require.NotNil(t, first.SourceLocation, "file_path/line must promote to sourceLocation")
	require.NotNil(t, first.SourceLocation.Ref)
	assert.Equal(t, "src/first.cpp", *first.SourceLocation.Ref)
	require.NotNil(t, first.SourceLocation.Line)
	assert.Equal(t, float64(13), *first.SourceLocation.Line)

	second := byID["DefectDojo-Finding-2"]
	require.NotNil(t, second.SourceLocation)
	assert.Equal(t, "src/two.cpp", *second.SourceLocation.Ref)
	require.NotNil(t, second.SourceLocation.Line)
	assert.Equal(t, float64(135), *second.SourceLocation.Line)

	// Line serializes as a bare integer (byte-parity with the TS twin).
	out, err := json.Marshal(first.SourceLocation)
	require.NoError(t, err)
	assert.JSONEq(t, `{"ref":"src/first.cpp","line":13}`, string(out))
}

// TestBuildSourceLocation_Branches covers every branch: primary file_path/line,
// the SAST fallback when file_path is absent, ref-only when line is absent, and
// the omit branch when the finding carries no locus at all.
func TestBuildSourceLocation_Branches(t *testing.T) {
	path := "src/a.go"
	line := 42

	// primary file_path/line
	loc := buildSourceLocation(ddFinding{FilePath: &path, Line: &line})
	require.NotNil(t, loc)
	assert.Equal(t, "src/a.go", *loc.Ref)
	require.NotNil(t, loc.Line)
	assert.Equal(t, float64(42), *loc.Line)

	// file_path present, line absent → ref only, line omitted
	locNoLine := buildSourceLocation(ddFinding{FilePath: &path})
	require.NotNil(t, locNoLine)
	assert.Equal(t, "src/a.go", *locNoLine.Ref)
	assert.Nil(t, locNoLine.Line, "line omitted when source line is absent")

	// file_path absent → SAST source fallback used instead
	sastPath := "sast/b.go"
	sastLine := 7
	locSast := buildSourceLocation(ddFinding{SastSourceFile: &sastPath, SastSourceLine: &sastLine})
	require.NotNil(t, locSast)
	assert.Equal(t, "sast/b.go", *locSast.Ref)
	require.NotNil(t, locSast.Line)
	assert.Equal(t, float64(7), *locSast.Line)

	// file_path present wins over SAST even when both are set
	locBoth := buildSourceLocation(ddFinding{FilePath: &path, Line: &line, SastSourceFile: &sastPath, SastSourceLine: &sastLine})
	require.NotNil(t, locBoth)
	assert.Equal(t, "src/a.go", *locBoth.Ref, "file_path takes precedence over sast_source_file_path")

	// no locus at all → omitted
	assert.Nil(t, buildSourceLocation(ddFinding{Title: "t"}), "no path → sourceLocation omitted")
	empty := ""
	assert.Nil(t, buildSourceLocation(ddFinding{FilePath: &empty}), "empty file_path → sourceLocation omitted")
}

// TestConvertFinding_NoSourceLocation covers the caller branch that leaves
// sourceLocation unset for a finding with no file locus.
func TestConvertFinding_NoSourceLocation(t *testing.T) {
	req := convertFinding(ddFinding{Title: "t", Severity: "High"})
	assert.Nil(t, req.SourceLocation, "no source path → sourceLocation unset")
}

func TestConvertDefectDojo_Empty(t *testing.T) {
	result, err := ConvertDefectDojo(loadFixture(t, "empty.json"), converterVersion)
	require.NoError(t, err)
	require.Len(t, result.Baselines, 1)
	require.Len(t, result.Baselines[0].Requirements, 1)
	req := result.Baselines[0].Requirements[0]
	assert.Equal(t, "defectdojo-no-findings", req.ID)
	assert.Equal(t, hdf.Passed, req.Results[0].Status)

	out, err := json.Marshal(result)
	require.NoError(t, err)
	assert.True(t, validators.ValidateResults(out).Valid)
}

func TestConvertDefectDojo_InvalidAndEmptyInput(t *testing.T) {
	_, err := ConvertDefectDojo([]byte(""), converterVersion)
	assert.Error(t, err)

	_, err = ConvertDefectDojo([]byte("not json"), converterVersion)
	assert.Error(t, err)

	// A malformed finding element exercises ddFinding.UnmarshalJSON's error path.
	_, err = ConvertDefectDojo([]byte(`[{"id":"not-an-int"}]`), converterVersion)
	assert.Error(t, err)
}
