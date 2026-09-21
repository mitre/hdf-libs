package gitlab_vulnerabilities_to_hdf

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

const rfc3339 = "2006-01-02T15:04:05Z"

func stamp(ts time.Time) string { return ts.UTC().Format(rfc3339) }

func statusPtr(s hdf.ResultStatus) *hdf.ResultStatus { return &s }

// One row of the triage-state mapping, asserted against a recorded finding.
type mappingRow struct {
	gid           string
	state         string
	reason        string
	rawStatus     hdf.ResultStatus
	overrideType  *hdf.OverrideType
	overrideTo    *hdf.ResultStatus
	justification *hdf.Justification
	effective     *hdf.ResultStatus
	appliedAt     string
	comment       string
}

func overrideTypePtr(t hdf.OverrideType) *hdf.OverrideType { return &t }

func justificationPtr(j hdf.Justification) *hdf.Justification { return &j }

func TestConvert_MappingRows(t *testing.T) {
	result := convertFixture(t, "triaged.json")
	rows := []mappingRow{
		{gid: "43", state: "DETECTED", rawStatus: hdf.Failed},
		{gid: "97", state: "CONFIRMED", rawStatus: hdf.Failed},
		{gid: "91", state: "RESOLVED", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.Attestation), overrideTo: statusPtr(hdf.Passed), effective: statusPtr(hdf.Passed), appliedAt: "2026-09-21T02:20:22Z", comment: "Reviewed with the application team and fixed in the 20.2.1 branch; the default branch scan has not picked up the fix yet."},
		{gid: "100", state: "RESOLVED", rawStatus: hdf.Passed},
		{gid: "50", state: "DISMISSED", reason: "FALSE_POSITIVE", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.FalsePositive), overrideTo: statusPtr(hdf.NotApplicable), effective: statusPtr(hdf.NotApplicable), appliedAt: "2026-09-20T19:27:19Z", comment: "The flagged value is a documented demo credential, not a real secret."},
		{gid: "1", state: "DISMISSED", reason: "ACCEPTABLE_RISK", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.OverrideTypeWaiver), overrideTo: statusPtr(hdf.Passed), effective: statusPtr(hdf.Passed), appliedAt: "2026-09-20T19:27:19Z", comment: "Outbound requests are restricted by the egress proxy; residual risk accepted by the product owner."},
		{gid: "94", state: "DISMISSED", reason: "MITIGATING_CONTROL", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.OverrideTypeWaiver), overrideTo: statusPtr(hdf.Passed), justification: justificationPtr(hdf.InlineMitigationsAlreadyExist), effective: statusPtr(hdf.Passed), appliedAt: "2026-09-20T19:27:20Z", comment: "Request body size is capped by the reverse proxy, bounding the loop."},
		{gid: "88", state: "DISMISSED", reason: "USED_IN_TESTS", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.OverrideTypeWaiver), overrideTo: statusPtr(hdf.NotApplicable), justification: justificationPtr(hdf.VulnerableCodeNotInExecutePath), effective: statusPtr(hdf.NotApplicable), appliedAt: "2026-09-20T19:27:20Z", comment: "Only reachable from the coding-challenge sandbox, which is not shipped to production."},
		{gid: "85", state: "DISMISSED", reason: "NOT_APPLICABLE", rawStatus: hdf.Failed, overrideType: overrideTypePtr(hdf.OverrideTypeWaiver), overrideTo: statusPtr(hdf.NotApplicable), effective: statusPtr(hdf.NotApplicable), appliedAt: "2026-09-20T19:27:20Z", comment: "The regular expression source is a build-time constant, not user input."},
	}
	for _, row := range rows {
		t.Run(row.state+"/"+row.reason+"/"+row.gid, func(t *testing.T) {
			req := requirementByGID(t, result, row.gid)
			require.Len(t, req.Results, 1)
			assert.Equal(t, row.rawStatus, req.Results[0].Status, "raw status")
			assert.Equal(t, row.state, req.Tags["gitlab/state"])
			if row.reason == "" {
				assert.Nil(t, req.Tags["gitlab/dismissalReason"])
			} else {
				assert.Equal(t, row.reason, req.Tags["gitlab/dismissalReason"])
			}

			if row.overrideType == nil {
				assert.Empty(t, req.StatusOverrides, "no override for %s", row.state)
				assert.Nil(t, req.Disposition)
				assert.Nil(t, req.EffectiveStatus, "effective posture is only emitted when an override exists")
				return
			}
			require.Len(t, req.StatusOverrides, 1)
			o := req.StatusOverrides[0]
			assert.Equal(t, *row.overrideType, o.Type)
			require.NotNil(t, o.Status)
			assert.Equal(t, *row.overrideTo, *o.Status)
			assert.Equal(t, row.comment, o.Reason)
			assert.Equal(t, row.appliedAt, stamp(o.AppliedAt))
			assert.Equal(t, o.AppliedAt.AddDate(1, 0, 0), o.ExpiresAt)
			assert.Equal(t, hdf.Identity{Type: hdf.Username, Identifier: "sec-reviewer", Description: strPtr("Security Reviewer")}, o.AppliedBy)
			if row.justification == nil {
				assert.Nil(t, o.Justification)
			} else {
				require.NotNil(t, o.Justification)
				assert.Equal(t, *row.justification, *o.Justification)
			}
			require.NotNil(t, req.Disposition)
			assert.Equal(t, *row.overrideType, *req.Disposition)
			require.NotNil(t, req.EffectiveStatus)
			assert.Equal(t, *row.effective, *req.EffectiveStatus)
			assert.Nil(t, req.EffectiveImpact, "status overrides never change impact")
		})
	}
}

func strPtr(s string) *string { return &s }

// Finding 80 was dismissed as ACCEPTABLE_RISK, reverted, then dismissed again
// as FALSE_POSITIVE. Both decisions stay in the record; the revert closes the
// first by expiring it at the revert time, so only the second governs.
func TestConvert_RevertHistory_KeepsBothOverridesAndExpiresTheReverted(t *testing.T) {
	req := requirementByGID(t, convertFixture(t, "triaged.json"), "80")

	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	require.Len(t, req.StatusOverrides, 2, "one override per decision, none for the revert")

	current, superseded := req.StatusOverrides[0], req.StatusOverrides[1]
	assert.Equal(t, hdf.FalsePositive, current.Type)
	assert.Equal(t, "Second review: the origin check compares against a fixed constant; scanner pattern is a false match.", current.Reason)
	assert.Equal(t, current.AppliedAt.AddDate(1, 0, 0), current.ExpiresAt)

	assert.Equal(t, hdf.OverrideTypeWaiver, superseded.Type)
	assert.Equal(t, "Initial triage: accepted pending review.", superseded.Reason)
	assert.Equal(t, "2026-09-20T19:27:20Z", stamp(superseded.ExpiresAt), "expired at the revert, not a year later")
	assert.False(t, superseded.ExpiresAt.After(superseded.AppliedAt), "the revert landed in the same second as the decision it undid")

	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.FalsePositive, *req.Disposition)
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.NotApplicable, *req.EffectiveStatus)
	assert.Equal(t, 3, req.Tags["gitlab/stateTransitionCount"])
	assert.Nil(t, req.Tags["gitlab/stateHistoryInconsistent"])
}

// Finding 66 had its severity lowered from MEDIUM to LOW by a human. The
// requirement keeps the scanner's impact; the change is an impact-only
// riskAdjustment that governs effectiveImpact and disposition but leaves the
// status ladder alone.
func TestConvert_SeverityOverride_IsImpactOnlyRiskAdjustment(t *testing.T) {
	req := requirementByGID(t, convertFixture(t, "triaged.json"), "66")

	assert.InDelta(t, 0.5, req.Impact, 1e-9, "impact from the original MEDIUM severity")
	assert.Equal(t, "MEDIUM", req.Tags["gitlab/originalSeverity"])
	assert.Equal(t, "LOW", req.Tags["gitlab/severity"])
	assert.Equal(t, hdf.Failed, req.Results[0].Status)

	require.Len(t, req.StatusOverrides, 1)
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.RiskAdjustment, o.Type)
	assert.Nil(t, o.Status, "riskAdjustment never carries a status")
	require.NotNil(t, o.Impact)
	assert.InDelta(t, 0.3, o.Impact.Value, 1e-9)
	assert.Equal(t, "Severity changed from MEDIUM to LOW in GitLab", o.Reason)
	assert.Equal(t, "2026-09-20T19:30:42Z", stamp(o.AppliedAt))
	assert.Equal(t, "sec-reviewer", o.AppliedBy.Identifier)

	require.NotNil(t, req.EffectiveImpact)
	assert.InDelta(t, 0.3, *req.EffectiveImpact, 1e-9)
	require.NotNil(t, req.Disposition)
	assert.Equal(t, hdf.RiskAdjustment, *req.Disposition)
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Failed, *req.EffectiveStatus, "no status override, so the ladder rolls up the raw result")
}

// The automatic falsePositive flag and the scanner-side resolved flag are
// heuristics, not decisions: they are carried as tags on every requirement and
// never produce an override. The recorded corpus has exactly one finding the
// scanner stopped reporting and no automatic false positive, which is pinned
// so a future re-record that flips either is noticed.
func TestConvert_HeuristicFlags_AreTagsOnly(t *testing.T) {
	result := convertFixture(t, "triaged.json")
	seen, resolvedOnBranch := 0, 0
	for _, b := range result.Baselines {
		for _, r := range b.Requirements {
			seen++
			assert.Equal(t, false, r.Tags["gitlab/falsePositive"], r.ID)
			assert.Equal(t, true, r.Tags["gitlab/presentOnDefaultBranch"], r.ID)
			if r.Tags["gitlab/resolvedOnDefaultBranch"] == true {
				resolvedOnBranch++
			}
		}
	}
	assert.Equal(t, 100, seen)
	assert.Equal(t, 1, resolvedOnBranch)
}

// Finding 100 is a finding the scanner stopped reporting and a human then
// marked resolved: a genuine pass at the raw level, with no override needed to
// attest it.
func TestConvert_ResolvedOnDefaultBranch_IsRawPassedWithoutOverride(t *testing.T) {
	req := requirementByGID(t, convertFixture(t, "triaged.json"), "100")

	assert.Equal(t, hdf.Passed, req.Results[0].Status)
	assert.Empty(t, req.StatusOverrides, "scanner evidence needs no attestation")
	assert.Nil(t, req.Disposition)
	assert.Nil(t, req.EffectiveStatus)
	assert.Equal(t, true, req.Tags["gitlab/resolvedOnDefaultBranch"])
	assert.Equal(t, "RESOLVED", req.Tags["gitlab/state"])
	assert.Equal(t, "sec-reviewer", req.Tags["gitlab/resolvedBy"])
}

// GitLab reverts a resolution itself when a later scan re-detects the finding.
// The attestation stays in the record, closed at the revert, and the
// requirement reads as failed again.
func TestConvert_ScannerRevertedResolution_ExpiresTheAttestation(t *testing.T) {
	req := requirementByGID(t, convertFixture(t, "triaged.json"), "72")

	assert.Equal(t, "DETECTED", req.Tags["gitlab/state"])
	assert.Equal(t, hdf.Failed, req.Results[0].Status)
	require.Len(t, req.StatusOverrides, 1, "the resolution is kept as history")
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.Attestation, o.Type)
	assert.Equal(t, "Fixed by validating redirect targets against an allow-list.", o.Reason)
	assert.Equal(t, "2026-09-20T19:27:19Z", stamp(o.AppliedAt))
	assert.Equal(t, "2026-09-21T02:04:51Z", stamp(o.ExpiresAt), "expired at the re-detection, not a year later")
	assert.Nil(t, req.Disposition, "nothing non-expired governs")
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Failed, *req.EffectiveStatus)
}

// When GitLab returns a triaged state but no transition history, the
// governing override is synthesized from the current-state fields.
func TestConvert_NoHistory_SynthesizesOverrideFromCurrentState(t *testing.T) {
	input := readInput(t, "triaged.json")
	var env map[string]any
	require.NoError(t, json.Unmarshal(input, &env))
	var kept []any
	for _, v := range env["vulnerabilities"].([]any) {
		node := v.(map[string]any)
		if node["id"] == "gid://gitlab/Vulnerability/1" {
			node["stateTransitions"] = map[string]any{"nodes": []any{}}
			kept = append(kept, node)
		}
	}
	env["vulnerabilities"] = kept
	modified, err := json.Marshal(env)
	require.NoError(t, err)

	result, err := ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.NoError(t, err)
	req := requirementByGID(t, result, "1")
	require.Len(t, req.StatusOverrides, 1)
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, o.Type)
	assert.Equal(t, "Outbound requests are restricted by the egress proxy; residual risk accepted by the product owner.", o.Reason, "stateComment stands in for the missing transition comment")
	assert.Equal(t, "2026-09-20T19:27:19Z", stamp(o.AppliedAt), "dismissedAt stands in for the transition time")
	assert.Equal(t, "sec-reviewer", o.AppliedBy.Identifier)
	assert.Equal(t, 0, req.Tags["gitlab/stateTransitionCount"])
}

// A history whose newest transition disagrees with the current state is
// flagged, and the current state still wins.
func TestConvert_InconsistentHistory_IsFlaggedAndCurrentStateWins(t *testing.T) {
	input := readInput(t, "triaged.json")
	var env map[string]any
	require.NoError(t, json.Unmarshal(input, &env))
	var kept []any
	for _, v := range env["vulnerabilities"].([]any) {
		node := v.(map[string]any)
		if node["id"] == "gid://gitlab/Vulnerability/85" {
			node["state"] = "CONFIRMED"
			node["dismissalReason"] = nil
			kept = append(kept, node)
		}
	}
	env["vulnerabilities"] = kept
	modified, err := json.Marshal(env)
	require.NoError(t, err)

	result, err := ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.NoError(t, err)
	req := requirementByGID(t, result, "85")
	assert.Equal(t, true, req.Tags["gitlab/stateHistoryInconsistent"])
	require.Len(t, req.StatusOverrides, 1, "the historical dismissal is kept as history")
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.OverrideTypeWaiver, o.Type)
	assert.Equal(t, "2026-09-21T02:19:29Z", stamp(o.ExpiresAt), "the superseded dismissal is closed at the last state change, not left open")
	require.NotNil(t, req.EffectiveStatus)
	assert.Equal(t, hdf.Failed, *req.EffectiveStatus, "CONFIRMED is the current state, so the stale dismissal no longer governs")
	assert.Nil(t, req.Disposition, "no non-expired override remains to dispose the finding")
}

func TestConvert_DecisionWithoutAuthor_IsAttributedToTheSystem(t *testing.T) {
	input := readInput(t, "triaged.json")
	var env map[string]any
	require.NoError(t, json.Unmarshal(input, &env))
	var kept []any
	for _, v := range env["vulnerabilities"].([]any) {
		node := v.(map[string]any)
		if node["id"] == "gid://gitlab/Vulnerability/91" {
			node["stateTransitions"] = map[string]any{"nodes": []any{}}
			node["resolvedBy"] = nil
			node["stateComment"] = nil
			kept = append(kept, node)
		}
	}
	env["vulnerabilities"] = kept
	modified, err := json.Marshal(env)
	require.NoError(t, err)

	result, err := ConvertGitlabVulnerabilitiesToHDF(modified, testVersion)
	require.NoError(t, err)
	req := requirementByGID(t, result, "91")
	require.Len(t, req.StatusOverrides, 1)
	o := req.StatusOverrides[0]
	assert.Equal(t, hdf.IdentityTypeSystem, o.AppliedBy.Type)
	assert.Equal(t, "gitlab", o.AppliedBy.Identifier)
	assert.Equal(t, "Marked resolved in GitLab", o.Reason, "a decision with no statement gets a fixed reason, never fabricated prose")
	assert.True(t, strings.HasPrefix(*o.AppliedBy.Description, "GitLab automatic"))
}
