package amend

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const minimalResults = `{
  "baselines": [{
    "name": "test-baseline",
    "checksum": {"algorithm": "sha256", "value": "abc123"},
    "depends": [],
    "description": "Test baseline",
    "groups": [],
    "inspecVersion": "5.0.0",
    "requirements": [{
      "id": "AC-1",
      "impact": 0.5,
      "title": "Access Control Policy",
      "descriptions": [{"label": "default", "data": "test"}],
      "results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
      "tags": {},
      "code": null,
      "refs": [],
      "sourceLocation": {"line": 1, "ref": "test.rb"},
      "statusOverrides": [],
      "evidence": [],
      "poams": []
    }],
    "supports": []
  }],
  "statistics": {"duration": 0.1}
}`

const minimalAmendments = `{
  "name": "test-waivers",
  "overrides": [{
    "type": "waiver",
    "requirementId": "AC-1",
    "status": "passed",
    "reason": "Risk accepted",
    "appliedBy": {"type": "email", "identifier": "admin@example.com"},
    "appliedAt": "2026-03-01T00:00:00Z",
    "expiresAt": "2026-12-31T00:00:00Z"
  }]
}`

const multiOverrideAmendments = `{
  "name": "multi-waivers",
  "overrides": [
    {
      "type": "waiver",
      "requirementId": "AC-1",
      "status": "passed",
      "reason": "Risk accepted",
      "appliedBy": {"type": "email", "identifier": "admin@example.com"},
      "appliedAt": "2026-03-01T00:00:00Z",
      "expiresAt": "2026-12-31T00:00:00Z"
    },
    {
      "type": "attestation",
      "requirementId": "AC-2",
      "status": "passed",
      "reason": "Manually verified",
      "appliedBy": {"type": "email", "identifier": "auditor@example.com"},
      "appliedAt": "2026-03-01T00:00:00Z",
      "expiresAt": "2026-06-30T00:00:00Z"
    }
  ]
}`

const resultsWithTwoRequirements = `{
  "baselines": [{
    "name": "test-baseline",
    "checksum": {"algorithm": "sha256", "value": "abc123"},
    "depends": [],
    "description": "Test baseline",
    "groups": [],
    "inspecVersion": "5.0.0",
    "requirements": [
      {
        "id": "AC-1",
        "impact": 0.5,
        "title": "Access Control Policy",
        "descriptions": [{"label": "default", "data": "test"}],
        "results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
        "tags": {},
        "code": null,
        "refs": [],
        "sourceLocation": {"line": 1, "ref": "test.rb"},
        "statusOverrides": [],
        "evidence": [],
        "poams": []
      },
      {
        "id": "AC-2",
        "impact": 0.7,
        "title": "Account Management",
        "descriptions": [{"label": "default", "data": "test"}],
        "results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
        "tags": {},
        "code": null,
        "refs": [],
        "sourceLocation": {"line": 10, "ref": "test.rb"},
        "statusOverrides": [],
        "evidence": [],
        "poams": []
      }
    ],
    "supports": []
  }],
  "statistics": {"duration": 0.1}
}`

func TestMergeAmendments(t *testing.T) {
	t.Run("merge with matching requirement sets effectiveStatus", func(t *testing.T) {
		merged, err := MergeAmendments([]byte(minimalResults), []byte(minimalAmendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		assert.Equal(t, "passed", req["effectiveStatus"])

		overrides := req["statusOverrides"].([]interface{})
		require.Len(t, overrides, 1)
		so := overrides[0].(map[string]interface{})
		assert.Equal(t, "waiver", so["type"])
		assert.Equal(t, "passed", so["status"])
		assert.Equal(t, "Risk accepted", so["reason"])
	})

	t.Run("merge with no matching requirement leaves results unchanged", func(t *testing.T) {
		amendments := `{
			"name": "no-match",
			"overrides": [{
				"type": "waiver",
				"requirementId": "ZZ-999",
				"status": "passed",
				"reason": "No match",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2026-12-31T00:00:00Z"
			}]
		}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		// effectiveStatus should not be set (no match applied).
		_, hasEffective := req["effectiveStatus"]
		assert.False(t, hasEffective)

		overrides := req["statusOverrides"].([]interface{})
		assert.Empty(t, overrides)
	})

	t.Run("merge with empty overrides returns results unchanged", func(t *testing.T) {
		amendments := `{"name": "empty", "overrides": []}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		// No previousChecksum should be set when no overrides were applied.
		_, hasPrev := doc["previousChecksum"]
		assert.False(t, hasPrev)
	})

	t.Run("merge with multiple overrides applies all", func(t *testing.T) {
		merged, err := MergeAmendments([]byte(resultsWithTwoRequirements), []byte(multiOverrideAmendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})

		// AC-1 should have the waiver applied.
		req0 := reqs[0].(map[string]interface{})
		assert.Equal(t, "passed", req0["effectiveStatus"])

		// AC-2 should have the attestation applied.
		req1 := reqs[1].(map[string]interface{})
		assert.Equal(t, "passed", req1["effectiveStatus"])
	})

	t.Run("previousChecksum is set on merged output", func(t *testing.T) {
		merged, err := MergeAmendments([]byte(minimalResults), []byte(minimalAmendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		prevRaw, ok := doc["previousChecksum"]
		require.True(t, ok, "previousChecksum should be set")

		prev := prevRaw.(map[string]interface{})
		assert.Equal(t, "sha256", prev["algorithm"])
		assert.NotEmpty(t, prev["value"])

		// The checksum should be deterministic for the same input.
		expectedChecksum := computeSHA256([]byte(minimalResults))
		assert.Equal(t, expectedChecksum, prev["value"])
	})

	t.Run("invalid results JSON returns error", func(t *testing.T) {
		_, err := MergeAmendments([]byte("not json"), []byte(minimalAmendments))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse results JSON")
	})

	t.Run("invalid amendments JSON returns error", func(t *testing.T) {
		_, err := MergeAmendments([]byte(minimalResults), []byte("not json"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse amendments JSON")
	})

	t.Run("amendments with no overrides key returns results unchanged", func(t *testing.T) {
		amendments := `{"name": "no-overrides-key"}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		// Should still be valid JSON.
		baselines := doc["baselines"].([]interface{})
		require.Len(t, baselines, 1)
	})

	t.Run("merge respects baselineRef", func(t *testing.T) {
		resultsWithTwoBaselines := `{
			"baselines": [
				{
					"name": "baseline-a",
					"checksum": {"algorithm": "sha256", "value": "abc"},
					"depends": [], "description": "A", "groups": [],
					"inspecVersion": "5.0.0",
					"requirements": [{
						"id": "AC-1", "impact": 0.5,
						"descriptions": [{"label": "default", "data": "test"}],
						"results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
						"tags": {}, "code": null, "refs": [],
						"sourceLocation": {"line": 1, "ref": "test.rb"},
						"statusOverrides": [], "evidence": [], "poams": []
					}],
					"supports": []
				},
				{
					"name": "baseline-b",
					"checksum": {"algorithm": "sha256", "value": "def"},
					"depends": [], "description": "B", "groups": [],
					"inspecVersion": "5.0.0",
					"requirements": [{
						"id": "AC-1", "impact": 0.5,
						"descriptions": [{"label": "default", "data": "test"}],
						"results": [{"status": "failed", "codeDesc": "test", "startTime": "2026-01-01T00:00:00Z", "backtrace": []}],
						"tags": {}, "code": null, "refs": [],
						"sourceLocation": {"line": 1, "ref": "test.rb"},
						"statusOverrides": [], "evidence": [], "poams": []
					}],
					"supports": []
				}
			],
			"statistics": {"duration": 0.1}
		}`

		amendments := `{
			"name": "targeted",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"baselineRef": "baseline-b",
				"status": "passed",
				"reason": "Risk accepted",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2026-12-31T00:00:00Z"
			}]
		}`

		merged, err := MergeAmendments([]byte(resultsWithTwoBaselines), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})

		// baseline-a AC-1 should NOT be modified.
		bA := baselines[0].(map[string]interface{})
		reqA := bA["requirements"].([]interface{})[0].(map[string]interface{})
		_, hasEffective := reqA["effectiveStatus"]
		assert.False(t, hasEffective, "baseline-a AC-1 should not have effectiveStatus")

		// baseline-b AC-1 SHOULD be modified.
		bB := baselines[1].(map[string]interface{})
		reqB := bB["requirements"].([]interface{})[0].(map[string]interface{})
		assert.Equal(t, "passed", reqB["effectiveStatus"])
	})
}

func TestListOverrides(t *testing.T) {
	t.Run("lists overrides from amendments", func(t *testing.T) {
		amendments := `{
			"name": "Q1 Waivers",
			"systemRef": "portal-prod.hdf-system.json",
			"overrides": [
				{
					"type": "waiver",
					"requirementId": "AC-1",
					"status": "passed",
					"reason": "Risk accepted",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2026-03-01T00:00:00Z",
					"expiresAt": "2026-06-30T00:00:00Z"
				}
			]
		}`
		name, sysRef, overrides, err := ListOverrides([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, "Q1 Waivers", name)
		assert.Equal(t, "portal-prod.hdf-system.json", sysRef)
		require.Len(t, overrides, 1)
		assert.Equal(t, "AC-1", overrides[0].RequirementID)
		assert.Equal(t, "waiver", overrides[0].Type)
		assert.Equal(t, "passed", overrides[0].Status)
	})

	t.Run("returns empty list for no overrides", func(t *testing.T) {
		amendments := `{"name": "empty"}`
		name, _, overrides, err := ListOverrides([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, "empty", name)
		assert.Empty(t, overrides)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		_, _, _, err := ListOverrides([]byte("not json"))
		require.Error(t, err)
	})
}

func TestVerifyAmendments(t *testing.T) {
	t.Run("all overrides valid (future expiration)", func(t *testing.T) {
		amendments := `{
			"name": "valid",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 1, result.TotalOverrides)
		assert.Equal(t, 1, result.ValidOverrides)
		assert.Equal(t, 0, result.ExpiredCount)
		assert.False(t, result.HasErrors)
	})

	t.Run("expired override detected", func(t *testing.T) {
		amendments := `{
			"name": "expired",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2020-01-01T00:00:00Z",
				"expiresAt": "2020-06-30T00:00:00Z"
			}]
		}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 1, result.TotalOverrides)
		assert.Equal(t, 0, result.ValidOverrides)
		assert.Equal(t, 1, result.ExpiredCount)
		assert.True(t, result.HasErrors)
	})

	t.Run("empty overrides", func(t *testing.T) {
		amendments := `{"name": "empty"}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 0, result.TotalOverrides)
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		_, err := VerifyAmendments([]byte("bad"))
		require.Error(t, err)
	})
}

func TestMergeAmendments_ImpactOverride(t *testing.T) {
	t.Run("risk adjustment sets effectiveImpact and disposition", func(t *testing.T) {
		amendments := `{
			"name": "risk-adjustments",
			"overrides": [{
				"type": "riskAdjustment",
				"requirementId": "AC-1",
				"impact": {"value": 0.3},
				"reason": "Dead code path",
				"appliedBy": {"type": "email", "identifier": "dev@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2026-12-31T00:00:00Z"
			}]
		}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		// effectiveStatus should NOT be set (impact-only override)
		_, hasEffectiveStatus := req["effectiveStatus"]
		assert.False(t, hasEffectiveStatus, "impact-only override should not set effectiveStatus")

		// effectiveImpact should be set
		assert.Equal(t, 0.3, req["effectiveImpact"])

		// disposition should be set
		assert.Equal(t, "riskAdjustment", req["disposition"])

		// statusOverrides should include the impact field
		overrides := req["statusOverrides"].([]interface{})
		require.Len(t, overrides, 1)
		so := overrides[0].(map[string]interface{})
		assert.Equal(t, "riskAdjustment", so["type"])
		impactObj := so["impact"].(map[string]interface{})
		assert.Equal(t, 0.3, impactObj["value"])
	})

	t.Run("override with both status and impact sets all three fields", func(t *testing.T) {
		amendments := `{
			"name": "combined",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"impact": {"value": 0.3},
				"reason": "AO accepted risk with severity lowered",
				"appliedBy": {"type": "email", "identifier": "ao@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2026-12-31T00:00:00Z"
			}]
		}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		assert.Equal(t, "passed", req["effectiveStatus"])
		assert.Equal(t, 0.3, req["effectiveImpact"])
		assert.Equal(t, "waiver", req["disposition"])
	})

	t.Run("falsePositive override sets disposition", func(t *testing.T) {
		amendments := `{
			"name": "fp-test",
			"overrides": [{
				"type": "falsePositive",
				"requirementId": "AC-1",
				"status": "notApplicable",
				"reason": "Scanner was wrong",
				"appliedBy": {"type": "email", "identifier": "dev@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2026-12-31T00:00:00Z"
			}]
		}`
		merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
		require.NoError(t, err)

		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(merged, &doc))

		baselines := doc["baselines"].([]interface{})
		baseline := baselines[0].(map[string]interface{})
		reqs := baseline["requirements"].([]interface{})
		req := reqs[0].(map[string]interface{})

		assert.Equal(t, "notApplicable", req["effectiveStatus"])
		assert.Equal(t, "falsePositive", req["disposition"])
	})
}

func TestListOverrides_WithImpact(t *testing.T) {
	amendments := `{
		"name": "impact-test",
		"overrides": [{
			"type": "riskAdjustment",
			"requirementId": "AC-1",
			"impact": {"value": 0.3},
			"reason": "Dead code path",
			"appliedBy": {"type": "email", "identifier": "dev@example.com"},
			"appliedAt": "2026-03-01T00:00:00Z",
			"expiresAt": "2026-12-31T00:00:00Z"
		}]
	}`
	_, _, overrides, err := ListOverrides([]byte(amendments))
	require.NoError(t, err)
	require.Len(t, overrides, 1)
	assert.Equal(t, "riskAdjustment", overrides[0].Type)
	assert.Equal(t, "", overrides[0].Status)
	require.NotNil(t, overrides[0].Impact)
	assert.Equal(t, 0.3, *overrides[0].Impact)
}

func TestMergeAmendments_InvalidStatusValues(t *testing.T) {
	tests := []struct {
		name       string
		statusJSON string
		desc       string
	}{
		{"invalid string", `"EVIL_INJECTION"`, "invalid status string should not set effectiveStatus"},
		{"non-string type", `42`, "non-string status should not set effectiveStatus"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			amendments := fmt.Sprintf(`{
				"name": "bad-status-test",
				"overrides": [{
					"type": "waiver",
					"requirementId": "AC-1",
					"status": %s,
					"reason": "test",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2026-03-01T00:00:00Z",
					"expiresAt": "2026-12-31T00:00:00Z"
				}]
			}`, tc.statusJSON)
			merged, err := MergeAmendments([]byte(minimalResults), []byte(amendments))
			require.NoError(t, err)

			var doc map[string]interface{}
			require.NoError(t, json.Unmarshal(merged, &doc))

			baselines := doc["baselines"].([]interface{})
			baseline := baselines[0].(map[string]interface{})
			reqs := baseline["requirements"].([]interface{})
			req := reqs[0].(map[string]interface{})

			_, hasEffective := req["effectiveStatus"]
			assert.False(t, hasEffective, tc.desc)
		})
	}
}
