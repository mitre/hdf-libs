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
    "expiresAt": "2099-12-31T00:00:00Z"
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
      "expiresAt": "2099-12-31T00:00:00Z"
    },
    {
      "type": "attestation",
      "requirementId": "AC-2",
      "status": "passed",
      "reason": "Manually verified",
      "appliedBy": {"type": "email", "identifier": "auditor@example.com"},
      "appliedAt": "2026-03-01T00:00:00Z",
      "expiresAt": "2099-12-31T00:00:00Z"
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

func TestMergeAmendments_RefusesDraft(t *testing.T) {
	draft := `{
		"_draft": true,
		"name": "draft",
		"overrides": [{
			"type": "waiver",
			"requirementId": "AC-1",
			"status": "passed",
			"reason": "",
			"appliedBy": {"type": "", "identifier": ""},
			"appliedAt": "2026-03-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z"
		}]
	}`
	_, err := MergeAmendments([]byte(minimalResults), []byte(draft))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "draft")
}

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
				"expiresAt": "2099-12-31T00:00:00Z"
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
				"expiresAt": "2099-12-31T00:00:00Z"
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
					"expiresAt": "2099-12-31T00:00:00Z"
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
				"expiresAt": "2099-12-31T00:00:00Z"
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
				"expiresAt": "2099-12-31T00:00:00Z"
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
				"expiresAt": "2099-12-31T00:00:00Z"
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
			"expiresAt": "2099-12-31T00:00:00Z"
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
					"expiresAt": "2099-12-31T00:00:00Z"
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

func TestMergeAmendments_StampsEffectiveChecksum(t *testing.T) {
	merged, err := MergeAmendments([]byte(minimalResults), []byte(minimalAmendments))
	require.NoError(t, err)

	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(merged, &doc))
	baselines := doc["baselines"].([]interface{})
	reqs := baselines[0].(map[string]interface{})["requirements"].([]interface{})
	req := reqs[0].(map[string]interface{})

	csRaw, ok := req["effectiveChecksum"]
	require.True(t, ok, "merged requirement must carry effectiveChecksum")
	cs := csRaw.(map[string]interface{})
	assert.Equal(t, "sha256", cs["algorithm"])
	// waiver: status passed, impact 0.5, disposition waiver
	// sha256 of {"status":"passed","impact":0.5,"disposition":"waiver"}
	assert.Equal(t, "d11c074ab9131807816013a71d986f1ceb2e5871a8a01dee4043391b7a6bf37b", cs["value"])
}

// chainedAmendments builds an amendments document whose overrides are linked by
// previousChecksum, exactly as `hdf amend create` writes them.
func chainedAmendments(t *testing.T, overrides ...map[string]interface{}) []byte {
	t.Helper()
	prev := ""
	for _, ov := range overrides {
		if prev != "" {
			ov["previousChecksum"] = map[string]interface{}{"algorithm": "sha256", "value": prev}
		}
		prev = ChecksumOverride(ov)
	}
	doc := map[string]interface{}{"name": "chained", "overrides": overrides}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

// waiverOverride returns a schema-valid waiver with the given id and reason.
func waiverOverride(id, reason string) map[string]interface{} {
	return map[string]interface{}{
		"type":          "waiver",
		"requirementId": id,
		"status":        "passed",
		"reason":        reason,
		"appliedBy":     map[string]interface{}{"type": "email", "identifier": "admin@example.com"},
		"appliedAt":     "2026-03-01T00:00:00Z",
		"expiresAt":     "2099-12-31T00:00:00Z",
	}
}

// retamper rewrites one field of one override and returns the document with the
// recorded previousChecksum values left untouched — the edit-in-place attack.
func retamper(t *testing.T, doc []byte, index int, key string, value interface{}) []byte {
	t.Helper()
	var parsed map[string]interface{}
	require.NoError(t, json.Unmarshal(doc, &parsed))
	overrides, ok := parsed["overrides"].([]interface{})
	require.True(t, ok)
	ov, ok := overrides[index].(map[string]interface{})
	require.True(t, ok)
	ov[key] = value
	raw, err := json.Marshal(parsed)
	require.NoError(t, err)
	return raw
}

func TestChecksumOverride(t *testing.T) {
	// Pins the canonical form the chain hashes. If this constant has to change,
	// every previously written chain stops verifying — treat a failure here as a
	// compatibility break, not a stale expectation.
	t.Run("canonical form is pinned", func(t *testing.T) {
		ov := waiverOverride("AC-1", "Risk accepted")
		assert.Equal(t,
			"01e3f4089976acdb66b08b277a3f96dd9072c6aab11d0ce78bf5769a688b185a",
			ChecksumOverride(ov))
	})

	t.Run("key order and whitespace do not change the checksum", func(t *testing.T) {
		compact := `{"type":"waiver","requirementId":"AC-1","reason":"r"}`
		reordered := "{\n  \"reason\"  :  \"r\",\n  \"requirementId\": \"AC-1\",\n\n  \"type\": \"waiver\"\n}"
		var a, b map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(compact), &a))
		require.NoError(t, json.Unmarshal([]byte(reordered), &b))
		assert.Equal(t, ChecksumOverride(a), ChecksumOverride(b))
	})

	t.Run("characters Go escapes in JSON round-trip identically", func(t *testing.T) {
		ov := waiverOverride("AC-1", "vendor A&B says x<y — accepted é")
		raw, err := json.Marshal(map[string]interface{}{"overrides": []interface{}{ov}})
		require.NoError(t, err)
		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &parsed))
		roundTripped := parsed["overrides"].([]interface{})[0].(map[string]interface{})
		assert.Equal(t, ChecksumOverride(ov), ChecksumOverride(roundTripped))
	})
}

func TestVerifyAmendments_Chain(t *testing.T) {
	t.Run("intact chain verifies", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"),
			waiverOverride("AC-3", "third reason"))

		result, err := VerifyAmendments(doc)
		require.NoError(t, err)
		assert.True(t, result.Chain.Established)
		assert.True(t, result.Chain.Valid)
		assert.Empty(t, result.Chain.Breaks)
		assert.False(t, result.HasErrors)
	})

	// The bug this card exists for: rewriting a justification after the fact
	// while leaving the stale previousChecksum in place.
	t.Run("tampered reason is detected", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"),
			waiverOverride("AC-3", "third reason"))
		tampered := retamper(t, doc, 1, "reason", "TAMPERED - actually we just wanted it gone")

		result, err := VerifyAmendments(tampered)
		require.NoError(t, err)
		assert.False(t, result.Chain.Valid)
		require.Len(t, result.Chain.Breaks, 1)
		assert.Contains(t, result.Chain.Breaks[0], "AC-3")
		assert.True(t, result.HasErrors)
	})

	t.Run("tampered author is detected", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))
		tampered := retamper(t, doc, 0, "appliedBy",
			map[string]interface{}{"type": "email", "identifier": "someone-else@example.com"})

		result, err := VerifyAmendments(tampered)
		require.NoError(t, err)
		assert.False(t, result.Chain.Valid)
		assert.True(t, result.HasErrors)
	})

	t.Run("tampered status is detected", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))
		tampered := retamper(t, doc, 0, "status", "notApplicable")

		result, err := VerifyAmendments(tampered)
		require.NoError(t, err)
		assert.False(t, result.Chain.Valid)
		assert.True(t, result.HasErrors)
	})

	t.Run("reserialization does not false-positive", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"),
			waiverOverride("AC-3", "third reason"))

		// Round-trip through indented JSON: same content, different key order on
		// the wire and different whitespace.
		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(doc, &parsed))
		reserialized, err := json.MarshalIndent(parsed, "", "    ")
		require.NoError(t, err)
		require.NotEqual(t, doc, reserialized)

		result, err := VerifyAmendments(reserialized)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid)
		assert.Empty(t, result.Chain.Breaks)
		assert.False(t, result.HasErrors)
	})

	t.Run("first override without previousChecksum passes", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(doc, &parsed))
		first := parsed["overrides"].([]interface{})[0].(map[string]interface{})
		_, hasChecksum := first["previousChecksum"]
		require.False(t, hasChecksum, "fixture precondition: first override starts the chain")

		result, err := VerifyAmendments(doc)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid)
		assert.False(t, result.HasErrors)
	})

	// The schema types previousChecksum as an object, so spelling "no prior
	// amendment" as an explicit null is a structural error rather than a chain
	// break. Hashing still ignores it, so the chain itself stays intact.
	t.Run("explicit null on the first override is structural, not a chain break", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))
		withNull := retamper(t, doc, 0, "previousChecksum", nil)

		result, err := VerifyAmendments(withNull)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid)
		assert.Empty(t, result.Chain.Breaks)
		assert.Equal(t, 1, result.InvalidCount)
	})

	t.Run("no chain at all is not a failure", func(t *testing.T) {
		result, err := VerifyAmendments([]byte(multiOverrideAmendments))
		require.NoError(t, err)
		assert.False(t, result.Chain.Established)
		assert.Empty(t, result.Chain.Breaks)
		assert.False(t, result.HasErrors)
	})

	// A chain that stops partway is a deleted link, not an absent chain.
	t.Run("dropped link in an established chain is a break", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"),
			waiverOverride("AC-3", "third reason"))

		var parsed map[string]interface{}
		require.NoError(t, json.Unmarshal(doc, &parsed))
		third := parsed["overrides"].([]interface{})[2].(map[string]interface{})
		delete(third, "previousChecksum")
		stripped, err := json.Marshal(parsed)
		require.NoError(t, err)

		result, err := VerifyAmendments(stripped)
		require.NoError(t, err)
		assert.True(t, result.Chain.Established)
		assert.False(t, result.Chain.Valid)
		assert.True(t, result.HasErrors)
	})

	t.Run("single override cannot establish a chain", func(t *testing.T) {
		result, err := VerifyAmendments([]byte(minimalAmendments))
		require.NoError(t, err)
		assert.False(t, result.Chain.Established)
		assert.False(t, result.HasErrors)
	})
}

func TestVerifyAmendments_Structural(t *testing.T) {
	t.Run("missing required field counts as invalid, not expired", func(t *testing.T) {
		amendments := `{
			"name": "malformed",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "2099-12-31T00:00:00Z"
			}]
		}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 1, result.TotalOverrides)
		assert.Equal(t, 1, result.InvalidCount)
		assert.Equal(t, 0, result.ExpiredCount)
		assert.Equal(t, 0, result.ValidOverrides)
		assert.True(t, result.HasErrors)
		assert.NotEmpty(t, result.SchemaErrors)
	})

	t.Run("unparseable expiresAt counts as invalid", func(t *testing.T) {
		amendments := `{
			"name": "bad-date",
			"overrides": [{
				"type": "waiver",
				"requirementId": "AC-1",
				"status": "passed",
				"reason": "test",
				"appliedBy": {"type": "email", "identifier": "admin@example.com"},
				"appliedAt": "2026-03-01T00:00:00Z",
				"expiresAt": "whenever"
			}]
		}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 1, result.InvalidCount)
		assert.Equal(t, 0, result.ExpiredCount)
		assert.True(t, result.HasErrors)
	})

	t.Run("expired and invalid are counted separately", func(t *testing.T) {
		amendments := `{
			"name": "mixed",
			"overrides": [
				{
					"type": "waiver",
					"requirementId": "AC-1",
					"status": "passed",
					"reason": "lapsed",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2020-01-01T00:00:00Z",
					"expiresAt": "2020-06-30T00:00:00Z"
				},
				{
					"type": "waiver",
					"requirementId": "AC-2",
					"status": "passed",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2026-03-01T00:00:00Z",
					"expiresAt": "2099-12-31T00:00:00Z"
				},
				{
					"type": "waiver",
					"requirementId": "AC-3",
					"status": "passed",
					"reason": "live",
					"appliedBy": {"type": "email", "identifier": "admin@example.com"},
					"appliedAt": "2026-03-01T00:00:00Z",
					"expiresAt": "2099-12-31T00:00:00Z"
				}
			]
		}`
		result, err := VerifyAmendments([]byte(amendments))
		require.NoError(t, err)
		assert.Equal(t, 3, result.TotalOverrides)
		assert.Equal(t, 1, result.ExpiredCount)
		assert.Equal(t, 1, result.InvalidCount)
		assert.Equal(t, 1, result.ValidOverrides)
		assert.True(t, result.HasErrors)
	})

	// Keeps the three counts a partition of the total, so a summary can never
	// silently drop an override.
	t.Run("counts partition the total", func(t *testing.T) {
		for _, doc := range []string{minimalAmendments, multiOverrideAmendments} {
			result, err := VerifyAmendments([]byte(doc))
			require.NoError(t, err)
			assert.Equal(t, result.TotalOverrides,
				result.ValidOverrides+result.ExpiredCount+result.InvalidCount)
		}
	})

	// The schema requires at least one override; a file with none is not a
	// clean bill of health.
	t.Run("document with no overrides has errors", func(t *testing.T) {
		result, err := VerifyAmendments([]byte(`{"name": "empty"}`))
		require.NoError(t, err)
		assert.Equal(t, 0, result.TotalOverrides)
		assert.True(t, result.HasErrors)
		assert.NotEmpty(t, result.SchemaErrors)
	})
}

func TestVerifyAmendments_MalformedShapes(t *testing.T) {
	t.Run("overrides that is not an array returns an error", func(t *testing.T) {
		_, err := VerifyAmendments([]byte(`{"name": "x", "overrides": "not-an-array"}`))
		require.Error(t, err)
	})

	t.Run("override that is not an object counts as invalid", func(t *testing.T) {
		result, err := VerifyAmendments([]byte(`{"name": "x", "overrides": [42]}`))
		require.NoError(t, err)
		assert.Equal(t, 1, result.TotalOverrides)
		assert.Equal(t, 1, result.InvalidCount)
		assert.True(t, result.HasErrors)
	})

	t.Run("previousChecksum without a string value reads as absent", func(t *testing.T) {
		_, present := recordedPreviousChecksum(map[string]interface{}{
			"previousChecksum": map[string]interface{}{"algorithm": "sha256", "value": 7},
		})
		assert.False(t, present)

		_, present = recordedPreviousChecksum("not-an-object")
		assert.False(t, present)

		_, present = recordedPreviousChecksum(map[string]interface{}{"previousChecksum": "bare-string"})
		assert.False(t, present)
	})

	t.Run("override with no requirementId still gets a position label", func(t *testing.T) {
		assert.Equal(t, "override 3", overrideLabel(map[string]interface{}{}, 2))
		assert.Equal(t, "override 1", overrideLabel("not-an-object", 0))
	})
}

func TestChecksumOverride_NestedValues(t *testing.T) {
	// Nulls nested inside an array element are dropped too, so an override
	// carrying evidence[] hashes the same whether or not its optional fields
	// are spelled out as nulls.
	t.Run("nulls nested inside arrays are dropped", func(t *testing.T) {
		withNulls := map[string]interface{}{
			"type":      "waiver",
			"evidence":  []interface{}{map[string]interface{}{"type": "url", "value": "https://example.com", "caption": nil}},
			"signature": nil,
		}
		without := map[string]interface{}{
			"type":     "waiver",
			"evidence": []interface{}{map[string]interface{}{"type": "url", "value": "https://example.com"}},
		}
		assert.Equal(t, ChecksumOverride(without), ChecksumOverride(withNulls))
	})

	t.Run("array order still matters", func(t *testing.T) {
		forward := map[string]interface{}{"refs": []interface{}{"a", "b"}}
		reversed := map[string]interface{}{"refs": []interface{}{"b", "a"}}
		assert.NotEqual(t, ChecksumOverride(forward), ChecksumOverride(reversed))
	})
}

// The chain hash is a cross-language contract. These pin the two properties a
// reimplementation is most likely to get wrong.
func TestChecksumOverride_CrossLanguageContract(t *testing.T) {
	// Pinned THROUGH ChecksumOverride, not through a re-composition of the
	// primitives it uses: asserting on json.Marshal(withoutNulls(x)) here would
	// restate the implementation rather than test it, and would not notice
	// ChecksumOverride switching to a non-escaping encoder.
	t.Run("HTML escaping is part of the canonical form", func(t *testing.T) {
		ov := map[string]interface{}{"reason": "vendor A & B, version < 3 > 1"}
		assert.Equal(t,
			"31649cbc90c142c596cf2126c825aa6d8da74a3b36bc4254475945b3f51ba7ca",
			ChecksumOverride(ov),
			"canonical bytes HTML-escape &, < and > as \\u0026, \\u003c, \\u003e; "+
				"a reimplementation must reproduce that or chains will disagree")
	})

	t.Run("keys are sorted regardless of insertion order", func(t *testing.T) {
		forward := map[string]interface{}{"zeta": "1", "alpha": "2", "mid": "3"}
		reordered := map[string]interface{}{"mid": "3", "zeta": "1", "alpha": "2"}
		assert.Equal(t, ChecksumOverride(forward), ChecksumOverride(reordered))
	})
}

// A hash chain with no signed anchor cannot detect everything, and the docs make
// claims about what it does detect. These pin the gaps so the wording and the
// code cannot drift apart: if any of these starts being detected, the docs
// should say so; until then they must not promise it.
func TestVerifyAmendments_ChainLimits(t *testing.T) {
	build := func(t *testing.T) []byte {
		t.Helper()
		return chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"),
			waiverOverride("AC-3", "third reason"))
	}

	// Nothing chains after the last amendment, so nothing records its content.
	t.Run("UNDETECTED: the last amendment can be edited freely", func(t *testing.T) {
		tampered := retamper(t, build(t), 2, "reason", "TAMPERED")
		result, err := VerifyAmendments(tampered)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid, "known limit: the final link has no successor to record it")
	})

	// Truncation leaves every surviving link consistent.
	t.Run("UNDETECTED: trailing amendments can be dropped", func(t *testing.T) {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(build(t), &doc))
		doc["overrides"] = doc["overrides"].([]interface{})[:2]
		truncated, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyAmendments(truncated)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid, "known limit: truncation cannot be seen without an anchored head")
	})

	// Stripping every link disarms the check rather than failing it, because an
	// un-chained document is a legitimate shape (the VEX importers emit one).
	t.Run("UNDETECTED: deleting the whole chain disarms the check", func(t *testing.T) {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(build(t), &doc))
		for _, ovRaw := range doc["overrides"].([]interface{}) {
			delete(ovRaw.(map[string]interface{}), "previousChecksum")
		}
		doc["overrides"].([]interface{})[1].(map[string]interface{})["reason"] = "TAMPERED"
		stripped, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyAmendments(stripped)
		require.NoError(t, err)
		assert.False(t, result.Chain.Established, "known limit: no chain means nothing to contradict")
		assert.True(t, result.Chain.Valid)
	})

	// The hash covers overrides only, never the envelope around them.
	t.Run("UNDETECTED: document-level fields are outside the hash", func(t *testing.T) {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal(build(t), &doc))
		doc["name"] = "Renamed after the fact"
		doc["approvedBy"] = map[string]interface{}{"type": "email", "identifier": "attacker@example.com"}
		altered, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyAmendments(altered)
		require.NoError(t, err)
		assert.True(t, result.Chain.Valid, "known limit: the chain hashes overrides, not the envelope")
	})

	// A single override has no link at all — the shape of most fixtures.
	t.Run("UNDETECTED: a one-override document has no chain to check", func(t *testing.T) {
		result, err := VerifyAmendments([]byte(minimalAmendments))
		require.NoError(t, err)
		assert.False(t, result.Chain.Established)
	})
}

func TestRefuseUnverified(t *testing.T) {
	t.Run("a verifying document is accepted", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))
		assert.NoError(t, RefuseUnverified(doc))
	})

	t.Run("expired is refused and the reason names the expiry", func(t *testing.T) {
		expired := waiverOverride("AC-1", "lapsed")
		expired["expiresAt"] = "2020-06-30T00:00:00Z"
		expired["appliedAt"] = "2020-01-01T00:00:00Z"
		doc, err := json.Marshal(map[string]interface{}{
			"name": "expired", "overrides": []interface{}{expired},
		})
		require.NoError(t, err)

		refuseErr := RefuseUnverified(doc)
		require.Error(t, refuseErr)
		assert.Contains(t, refuseErr.Error(), "expired")
	})

	t.Run("a broken chain is refused and the reason names the link", func(t *testing.T) {
		doc := chainedAmendments(t,
			waiverOverride("AC-1", "first reason"),
			waiverOverride("AC-2", "second reason"))
		tampered := retamper(t, doc, 0, "reason", "TAMPERED")

		refuseErr := RefuseUnverified(tampered)
		require.Error(t, refuseErr)
		assert.Contains(t, refuseErr.Error(), "chain is broken")
		assert.Contains(t, refuseErr.Error(), "AC-2")
	})

	t.Run("structurally invalid is refused and the reason names the field", func(t *testing.T) {
		invalid := waiverOverride("AC-1", "")
		delete(invalid, "reason")
		doc, err := json.Marshal(map[string]interface{}{
			"name": "malformed", "overrides": []interface{}{invalid},
		})
		require.NoError(t, err)

		refuseErr := RefuseUnverified(doc)
		require.Error(t, refuseErr)
		assert.Contains(t, refuseErr.Error(), "reason is required")
	})

	// A draft's stubs are deliberately incomplete, so its own remedy is more
	// useful than the schema errors they produce.
	t.Run("a draft keeps its own more specific refusal", func(t *testing.T) {
		doc, err := json.Marshal(map[string]interface{}{
			"_draft": true, "name": "draft",
			"overrides": []interface{}{map[string]interface{}{"type": "waiver"}},
		})
		require.NoError(t, err)

		refuseErr := RefuseUnverified(doc)
		require.Error(t, refuseErr)
		assert.Contains(t, refuseErr.Error(), "draft")
		assert.NotContains(t, refuseErr.Error(), "does not verify")
	})

	t.Run("unparseable JSON is refused", func(t *testing.T) {
		require.Error(t, RefuseUnverified([]byte("not json")))
	})

	// The whole point of the gate: the two commands cannot disagree.
	t.Run("refuses exactly what verify reports as failing", func(t *testing.T) {
		cases := map[string][]byte{
			"clean": chainedAmendments(t, waiverOverride("AC-1", "a"), waiverOverride("AC-2", "b")),
			"tampered": retamper(t, chainedAmendments(t,
				waiverOverride("AC-1", "a"), waiverOverride("AC-2", "b")), 0, "reason", "T"),
			"noOverrides": []byte(`{"name": "empty"}`),
			"unchained":   []byte(multiOverrideAmendments),
		}
		for name, doc := range cases {
			result, err := VerifyAmendments(doc)
			require.NoError(t, err, name)
			if result.HasErrors {
				assert.Errorf(t, RefuseUnverified(doc), "%s: verify failed but apply allowed it", name)
			} else {
				assert.NoErrorf(t, RefuseUnverified(doc), "%s: verify passed but apply refused it", name)
			}
		}
	})
}

func TestVerifyResult_FailureSummary(t *testing.T) {
	t.Run("empty when the document verifies", func(t *testing.T) {
		assert.Empty(t, (&VerifyResult{}).FailureSummary())
	})

	t.Run("names every failing dimension", func(t *testing.T) {
		r := &VerifyResult{
			ExpiredCount: 2,
			InvalidCount: 1,
			SchemaErrors: []string{"overrides.0: reason is required"},
			Chain:        ChainStatus{Established: true, Valid: false},
		}
		assert.Equal(t, "2 expired, 1 invalid, amendment chain is broken", r.FailureSummary())
	})

	t.Run("a document-level schema error is named when no override owns it", func(t *testing.T) {
		r := &VerifyResult{SchemaErrors: []string{"overrides is required"}}
		assert.Equal(t, "document is invalid", r.FailureSummary())
	})

	t.Run("an unestablished chain is not a failure", func(t *testing.T) {
		r := &VerifyResult{Chain: ChainStatus{Established: false, Valid: true}}
		assert.Empty(t, r.FailureSummary())
	})
}

func TestVerifyChain(t *testing.T) {
	t.Run("no recorded results link is reported as not established", func(t *testing.T) {
		result, err := VerifyChain([]byte(minimalResults), []byte(minimalAmendments))
		require.NoError(t, err)
		assert.False(t, result.ChainEstablished)
		assert.Contains(t, result.ChainMessage, "records no checksum")
		assert.Empty(t, result.MissingReqIDs)
		assert.NotNil(t, result.ExpirationResult)
	})

	t.Run("a matching results link verifies", func(t *testing.T) {
		sum := computeSHA256([]byte(minimalResults))
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(minimalAmendments), &doc))
		doc["previousChecksum"] = map[string]interface{}{"algorithm": "sha256", "value": sum}
		linked, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyChain([]byte(minimalResults), linked)
		require.NoError(t, err)
		assert.True(t, result.ChainEstablished)
		assert.True(t, result.ChainValid)
	})

	t.Run("a mismatched results link fails", func(t *testing.T) {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(minimalAmendments), &doc))
		doc["previousChecksum"] = map[string]interface{}{
			"algorithm": "sha256",
			"value":     "0000000000000000000000000000000000000000000000000000000000000000",
		}
		linked, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyChain([]byte(minimalResults), linked)
		require.NoError(t, err)
		assert.True(t, result.ChainEstablished)
		assert.False(t, result.ChainValid)
		assert.Contains(t, result.ChainMessage, "mismatch")
	})

	// One amendments document may cover a fleet and be applied per host, so an
	// override naming an absent requirement is reported, not treated as fatal
	// by apply. Verify still surfaces it.
	t.Run("requirementIds absent from the results are listed", func(t *testing.T) {
		var doc map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(minimalAmendments), &doc))
		doc["overrides"].([]interface{})[0].(map[string]interface{})["requirementId"] = "NOT-THERE-1"
		altered, err := json.Marshal(doc)
		require.NoError(t, err)

		result, err := VerifyChain([]byte(minimalResults), altered)
		require.NoError(t, err)
		assert.Equal(t, []string{"NOT-THERE-1"}, result.MissingReqIDs)
		// Apply's gate is document-scoped and does not adopt this check.
		assert.NoError(t, RefuseUnverified(altered))
	})

	t.Run("expiry is carried through from the document check", func(t *testing.T) {
		expired := waiverOverride("AC-1", "lapsed")
		expired["expiresAt"] = "2020-06-30T00:00:00Z"
		doc, err := json.Marshal(map[string]interface{}{
			"name": "expired", "overrides": []interface{}{expired},
		})
		require.NoError(t, err)

		result, err := VerifyChain([]byte(minimalResults), doc)
		require.NoError(t, err)
		assert.Equal(t, 1, result.ExpirationResult.ExpiredCount)
		assert.True(t, result.ExpirationResult.HasErrors)
	})

	t.Run("unparseable input returns an error", func(t *testing.T) {
		_, err := VerifyChain([]byte(minimalResults), []byte("nope"))
		require.Error(t, err)

		_, err = VerifyChain([]byte("nope"), []byte(minimalAmendments))
		require.Error(t, err)
	})

	// Malformed entries in the results are skipped rather than panicking, so a
	// junk document still produces a verdict.
	t.Run("non-object baselines and requirements are skipped", func(t *testing.T) {
		junk := `{"baselines": [42, {"requirements": [7, {"id": "AC-1"}]}], "statistics": {"duration": 0.1}}`
		result, err := VerifyChain([]byte(junk), []byte(minimalAmendments))
		require.NoError(t, err)
		assert.Empty(t, result.MissingReqIDs, "AC-1 is present despite the junk entries")
	})
}

func TestChainOverrides(t *testing.T) {
	build := func() []map[string]interface{} {
		return []map[string]interface{}{
			waiverOverride("AC-1", "first"),
			waiverOverride("AC-2", "second"),
			waiverOverride("AC-3", "third"),
		}
	}

	t.Run("leaves the first unlinked and chains the rest", func(t *testing.T) {
		overrides := build()
		require.NoError(t, ChainOverrides(overrides))

		_, first := overrides[0]["previousChecksum"]
		assert.False(t, first)
		for i := 1; i < len(overrides); i++ {
			link, ok := overrides[i]["previousChecksum"].(map[string]interface{})
			require.Truef(t, ok, "override %d", i)
			assert.Equal(t, "sha256", link["algorithm"])
			assert.Equal(t, ChecksumOverride(overrides[i-1]), link["value"])
		}
	})

	t.Run("what it writes is what verify accepts", func(t *testing.T) {
		overrides := build()
		require.NoError(t, ChainOverrides(overrides))
		raw, err := json.Marshal(map[string]interface{}{"name": "chained", "overrides": overrides})
		require.NoError(t, err)

		result, err := VerifyAmendments(raw)
		require.NoError(t, err)
		assert.True(t, result.Chain.Established)
		assert.True(t, result.Chain.Valid, "%v", result.Chain.Breaks)
	})

	// A stale link on the first override would otherwise survive re-chaining and
	// be hashed into every downstream link.
	t.Run("a stale link on the first override is cleared", func(t *testing.T) {
		overrides := build()
		overrides[0]["previousChecksum"] = map[string]interface{}{"algorithm": "sha256", "value": "stale"}
		require.NoError(t, ChainOverrides(overrides))
		_, first := overrides[0]["previousChecksum"]
		assert.False(t, first)
	})

	t.Run("re-chaining is stable", func(t *testing.T) {
		overrides := build()
		require.NoError(t, ChainOverrides(overrides))
		before := overrides[2]["previousChecksum"]
		require.NoError(t, ChainOverrides(overrides))
		assert.Equal(t, before, overrides[2]["previousChecksum"])
	})

	t.Run("an empty set is a no-op", func(t *testing.T) {
		assert.NoError(t, ChainOverrides(nil))
	})

	// Fails closed: an unhashable override must abort rather than silently leave
	// the rest of the document unchained.
	t.Run("an unhashable override aborts", func(t *testing.T) {
		overrides := []map[string]interface{}{
			waiverOverride("AC-1", "first"),
			{"bad": make(chan int)},
		}
		err := ChainOverrides(overrides)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chaining override 1")
	})
}
