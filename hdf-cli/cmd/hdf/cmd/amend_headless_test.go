package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedNow is a deterministic clock for tests.
func fixedNow() time.Time {
	return time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
}

// --- parseSpecInput ---

func TestParseSpecInput_Array(t *testing.T) {
	data := []byte(`[
		{"type":"attestation","requirementId":"AC-1","reason":"ok","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}
	]`)
	specs, envelope, err := parseSpecInput(data)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	assert.Equal(t, "attestation", specs[0]["type"])
	assert.Nil(t, envelope)
}

func TestParseSpecInput_Envelope(t *testing.T) {
	data := []byte(`{
		"name":"Custom Name",
		"approvedBy":{"type":"email","identifier":"ao@b.gov"},
		"overrides":[{"type":"waiver","requirementId":"AC-1","reason":"ok","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}]
	}`)
	specs, envelope, err := parseSpecInput(data)
	require.NoError(t, err)
	require.Len(t, specs, 1)
	require.NotNil(t, envelope)
	assert.Equal(t, "Custom Name", envelope["name"])
}

func TestParseSpecInput_EmptyArray(t *testing.T) {
	_, _, err := parseSpecInput([]byte(`[]`))
	require.Error(t, err)
}

func TestParseSpecInput_Garbage(t *testing.T) {
	_, _, err := parseSpecInput([]byte(`not json`))
	require.Error(t, err)
}

// --- fattenOverrideSpec ---

func TestFattenOverrideSpec_AppliedBySugar(t *testing.T) {
	spec := map[string]interface{}{
		"type": "attestation", "requirementId": "AC-1", "reason": "verified",
		"appliedBy": "assessor@agency.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	id, ok := out["appliedBy"].(map[string]interface{})
	require.True(t, ok, "appliedBy string should expand to an Identity object")
	assert.Equal(t, "email", id["type"])
	assert.Equal(t, "assessor@agency.gov", id["identifier"])
}

func TestFattenOverrideSpec_AppliedBySugarSimple(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": "jdoe", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	id := out["appliedBy"].(map[string]interface{})
	assert.Equal(t, "simple", id["type"])
}

func TestFattenOverrideSpec_AppliedByObjectKept(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": map[string]interface{}{"type": "username", "identifier": "svc"},
		"expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	id := out["appliedBy"].(map[string]interface{})
	assert.Equal(t, "username", id["type"])
}

func TestFattenOverrideSpec_AppliedAtDefaultsToNow(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "2026-05-28T12:00:00Z", out["appliedAt"])
}

func TestFattenOverrideSpec_AppliedAtKept(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": "a@b.gov", "appliedAt": "2026-01-02T03:04:05Z", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "2026-01-02T03:04:05Z", out["appliedAt"])
}

func TestFattenOverrideSpec_RelativeExpiry(t *testing.T) {
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1", "impact": 0.4,
		"reason": "internal only", "appliedBy": "a@b.gov", "expiresAt": "1y",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	exp, _ := out["expiresAt"].(string)
	assert.True(t, strings.HasPrefix(exp, "2027-05-28"), "1y from 2026-05-28 should resolve to 2027-05-28*, got %q", exp)
	assert.True(t, strings.HasSuffix(exp, "Z"), "expiry should be a full date-time")
}

func TestFattenOverrideSpec_AbsoluteDateTimeExpiryKept(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": "a@b.gov", "expiresAt": "2027-03-04T05:06:07Z", "status": "passed",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "2027-03-04T05:06:07Z", out["expiresAt"])
}

func TestFattenOverrideSpec_ImpactNumberSugar(t *testing.T) {
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1", "impact": 0.42,
		"reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	imp, ok := out["impact"].(map[string]interface{})
	require.True(t, ok, "numeric impact should expand to {value}")
	assert.InDelta(t, 0.42, imp["value"], 0.0001)
}

func TestFattenOverrideSpec_ImpactObjectKept(t *testing.T) {
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1",
		"impact": map[string]interface{}{"value": 0.3},
		"reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	imp := out["impact"].(map[string]interface{})
	assert.InDelta(t, 0.3, imp["value"], 0.0001)
}

func TestFattenOverrideSpec_DefaultStatusByType(t *testing.T) {
	// waiver with no explicit status gets the type default so the schema anyOf is satisfied.
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x",
		"appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "passed", out["status"])
}

func TestFattenOverrideSpec_ExplicitStatusKept(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "status": "notApplicable",
		"appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "notApplicable", out["status"])
}

func TestFattenOverrideSpec_RiskAdjustmentNoStatusWhenImpact(t *testing.T) {
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1", "impact": 0.3,
		"reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	_, hasStatus := out["status"]
	assert.False(t, hasStatus, "riskAdjustment with impact should not get a status")
}

func TestFattenOverrideSpec_MissingType(t *testing.T) {
	spec := map[string]interface{}{
		"requirementId": "AC-1", "reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_InvalidType(t *testing.T) {
	spec := map[string]interface{}{
		"type": "bogus", "requirementId": "AC-1", "reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_MissingRequirementID(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_MissingExpiresAt(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "appliedBy": "a@b.gov",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_CarriesThroughExtraFields(t *testing.T) {
	// cvss/evidence/milestones are passed through verbatim — fatten is type-agnostic.
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1", "impact": 0.4,
		"reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
		"cvss":     map[string]interface{}{"version": "4.0", "baseScore": 9.8},
		"evidence": []interface{}{map[string]interface{}{"type": "url", "data": "https://x"}},
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	assert.Contains(t, out, "cvss")
	assert.Contains(t, out, "evidence")
}

func TestFattenOverrideSpec_MissingAppliedBy(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_EmptyAppliedBy(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "appliedBy": "", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_InvalidAppliedByType(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "appliedBy": 42, "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_MissingReason(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_InvalidRelativeExpiry(t *testing.T) {
	spec := map[string]interface{}{
		"type": "waiver", "requirementId": "AC-1", "reason": "x", "appliedBy": "a@b.gov", "expiresAt": "soon",
	}
	_, err := fattenOverrideSpec(spec, fixedNow())
	require.Error(t, err)
}

func TestFattenOverrideSpec_ImpactJSONNumberSugar(t *testing.T) {
	// json.Number arrives when the spec is decoded with UseNumber (envelope path
	// preserves the raw type); ensure it still expands to {value}.
	spec := map[string]interface{}{
		"type": "riskAdjustment", "requirementId": "CVE-1", "impact": json.Number("0.55"),
		"reason": "x", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01",
	}
	out, err := fattenOverrideSpec(spec, fixedNow())
	require.NoError(t, err)
	imp := out["impact"].(map[string]interface{})
	assert.InDelta(t, 0.55, imp["value"], 0.0001)
}

// --- buildAmendmentsFromSpecs ---

func TestBuildAmendmentsFromSpecs_MultipleTypes(t *testing.T) {
	specs := []map[string]interface{}{
		{"type": "attestation", "requirementId": "SV-1", "status": "passed", "reason": "reviewed firewall", "appliedBy": "assessor@agency.gov", "expiresAt": "2027-01-01"},
		{"type": "waiver", "requirementId": "SV-2", "status": "notApplicable", "reason": "compensating control", "appliedBy": "ao@agency.gov", "expiresAt": "2027-02-01"},
		{"type": "riskAdjustment", "requirementId": "CVE-2021-44228", "impact": 0.42, "reason": "JNDI disabled", "appliedBy": "secops@agency.gov", "expiresAt": "6m"},
	}
	doc, err := buildAmendmentsFromSpecs(specs, nil, fixedNow())
	require.NoError(t, err)

	overrides := doc["overrides"].([]map[string]interface{})
	require.Len(t, overrides, 3)
	assert.Equal(t, "attestation", overrides[0]["type"])
	assert.Equal(t, "waiver", overrides[1]["type"])
	assert.Equal(t, "riskAdjustment", overrides[2]["type"])

	// Output must validate against the hdf-amendments schema.
	raw, marshalErr := json.Marshal(doc)
	require.NoError(t, marshalErr)
	res := validators.ValidateAmendments(raw)
	assert.True(t, res.Valid, "headless output must be schema-valid; errors: %v", res.Errors)
}

func TestBuildAmendmentsFromSpecs_PreviousChecksumChain(t *testing.T) {
	specs := []map[string]interface{}{
		{"type": "waiver", "requirementId": "SV-1", "status": "passed", "reason": "a", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01"},
		{"type": "waiver", "requirementId": "SV-2", "status": "passed", "reason": "b", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01"},
	}
	doc, err := buildAmendmentsFromSpecs(specs, nil, fixedNow())
	require.NoError(t, err)
	overrides := doc["overrides"].([]map[string]interface{})

	_, firstHasChecksum := overrides[0]["previousChecksum"]
	assert.False(t, firstHasChecksum, "first override has no previousChecksum")

	chk, ok := overrides[1]["previousChecksum"].(map[string]interface{})
	require.True(t, ok, "second override must chain to the first")
	assert.Equal(t, "sha256", chk["algorithm"])
	assert.NotEmpty(t, chk["value"])
}

func TestBuildAmendmentsFromSpecs_DerivesName(t *testing.T) {
	specs := []map[string]interface{}{
		{"type": "waiver", "requirementId": "SV-1", "status": "passed", "reason": "a", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01"},
	}
	doc, err := buildAmendmentsFromSpecs(specs, nil, fixedNow())
	require.NoError(t, err)
	name, _ := doc["name"].(string)
	assert.Contains(t, name, "waiver")
}

func TestBuildAmendmentsFromSpecs_EnvelopeNameKept(t *testing.T) {
	specs := []map[string]interface{}{
		{"type": "waiver", "requirementId": "SV-1", "status": "passed", "reason": "a", "appliedBy": "a@b.gov", "expiresAt": "2027-01-01"},
	}
	envelope := map[string]interface{}{
		"name":        "Portal Q1 Waivers",
		"description": "quarterly review",
		"approvedBy":  map[string]interface{}{"type": "email", "identifier": "ao@agency.gov"},
	}
	doc, err := buildAmendmentsFromSpecs(specs, envelope, fixedNow())
	require.NoError(t, err)
	assert.Equal(t, "Portal Q1 Waivers", doc["name"])
	assert.Equal(t, "quarterly review", doc["description"])
	assert.Contains(t, doc, "approvedBy")

	raw, _ := json.Marshal(doc)
	res := validators.ValidateAmendments(raw)
	assert.True(t, res.Valid, "envelope output must be schema-valid; errors: %v", res.Errors)
}

func TestBuildAmendmentsFromSpecs_InvalidSpecPropagates(t *testing.T) {
	specs := []map[string]interface{}{
		{"type": "waiver", "requirementId": "SV-1", "reason": "a", "appliedBy": "a@b.gov"}, // no expiresAt
	}
	_, err := buildAmendmentsFromSpecs(specs, nil, fixedNow())
	require.Error(t, err)
}

// --- buildDraftFromResults ---

func draftResultsDoc() map[string]interface{} {
	var doc map[string]interface{}
	_ = json.Unmarshal([]byte(testResults), &doc)
	return doc
}

func TestBuildDraftFromResults_EmitsStubsWithMarker(t *testing.T) {
	doc := draftResultsDoc()
	draft, err := buildDraftFromResults(doc, "attestation", "", "", "1y", fixedNow())
	require.NoError(t, err)

	marker, _ := draft["_draft"].(bool)
	assert.True(t, marker, "draft must carry the _draft marker")

	overrides := draft["overrides"].([]map[string]interface{})
	require.Len(t, overrides, 1)
	stub := overrides[0]
	assert.Equal(t, "attestation", stub["type"])
	assert.Equal(t, "AC-1", stub["requirementId"])
	assert.Equal(t, "", stub["reason"], "reason is left blank for the author")
	assert.Contains(t, stub, "_label", "stub carries a human-readable label")
	exp, _ := stub["expiresAt"].(string)
	assert.True(t, strings.HasPrefix(exp, "2027-05-28"), "expiresAt resolved from --expires")
}

func TestBuildDraftFromResults_RiskAdjustmentStub(t *testing.T) {
	doc := draftResultsDoc()
	draft, err := buildDraftFromResults(doc, "riskAdjustment", "", "", "", fixedNow())
	require.NoError(t, err)
	stub := draft["overrides"].([]map[string]interface{})[0]
	imp, ok := stub["impact"].(map[string]interface{})
	require.True(t, ok, "riskAdjustment stub gets an impact placeholder")
	assert.Contains(t, imp, "value")
	assert.NotContains(t, stub, "cvss", "foundation draft must not bake in a cvss block (child bead)")
}

func TestBuildDraftFromResults_StatusFilter(t *testing.T) {
	doc := draftResultsDoc()
	// The only requirement is failed; filtering for passed should yield nothing.
	draft, err := buildDraftFromResults(doc, "waiver", "passed", "", "", fixedNow())
	require.NoError(t, err)
	overrides, _ := draft["overrides"].([]map[string]interface{})
	assert.Empty(t, overrides)
}

func TestBuildDraftFromResults_SelectFilter(t *testing.T) {
	doc := draftResultsDoc()
	draft, err := buildDraftFromResults(doc, "waiver", "", "access control", "", fixedNow())
	require.NoError(t, err)
	overrides := draft["overrides"].([]map[string]interface{})
	require.Len(t, overrides, 1, "select substring should match the requirement title")

	draft2, err := buildDraftFromResults(doc, "waiver", "", "nonexistent", "", fixedNow())
	require.NoError(t, err)
	assert.Empty(t, draft2["overrides"].([]map[string]interface{}))
}

func TestBuildDraftFromResults_InvalidType(t *testing.T) {
	doc := draftResultsDoc()
	_, err := buildDraftFromResults(doc, "bogus", "", "", "", fixedNow())
	require.Error(t, err)
}

func TestParseSpecInput_EnvelopeNoOverrides(t *testing.T) {
	_, _, err := parseSpecInput([]byte(`{"name":"x"}`))
	require.Error(t, err)
}

func TestParseSpecInput_EnvelopeOverrideNotObject(t *testing.T) {
	_, _, err := parseSpecInput([]byte(`{"name":"x","overrides":["nope"]}`))
	require.Error(t, err)
}

func TestParseSpecInput_Empty(t *testing.T) {
	_, _, err := parseSpecInput([]byte("   "))
	require.Error(t, err)
}

func TestResolveDraftExpiry(t *testing.T) {
	now := fixedNow()
	got, err := resolveDraftExpiry("", now)
	require.NoError(t, err)
	assert.Equal(t, "", got)

	got, err = resolveDraftExpiry("2027-04-05T06:07:08Z", now)
	require.NoError(t, err)
	assert.Equal(t, "2027-04-05T06:07:08Z", got)

	got, err = resolveDraftExpiry("2028-01-01", now)
	require.NoError(t, err)
	assert.Equal(t, "2028-01-01T23:59:59Z", got)

	_, err = resolveDraftExpiry("whenever", now)
	require.Error(t, err)
}

func TestBuildDraftFromResults_InvalidExpires(t *testing.T) {
	doc := draftResultsDoc()
	_, err := buildDraftFromResults(doc, "waiver", "", "", "whenever", fixedNow())
	require.Error(t, err)
}

func TestBuildDraftFromResults_PoamStub(t *testing.T) {
	doc := draftResultsDoc()
	draft, err := buildDraftFromResults(doc, "poam", "", "", "", fixedNow())
	require.NoError(t, err)
	stub := draft["overrides"].([]map[string]interface{})[0]
	assert.Contains(t, stub, "milestones")
	assert.Contains(t, stub, "status")
}

func TestReadSpecInput_File(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "s.json")
	require.NoError(t, os.WriteFile(p, []byte(`[]`), 0o600))
	data, err := readSpecInput(p)
	require.NoError(t, err)
	assert.Equal(t, "[]", string(data))
}

func TestReadSpecInput_MissingFile(t *testing.T) {
	_, err := readSpecInput(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
}

// withStdin temporarily replaces os.Stdin with a pipe carrying content, so the
// "-"/non-TTY stdin path can be exercised in tests.
func withStdin(t *testing.T, content string, fn func()) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = orig }()
	go func() {
		_, _ = w.WriteString(content)
		_ = w.Close()
	}()
	fn()
}

func TestReadSpecInput_Stdin(t *testing.T) {
	withStdin(t, `[]`, func() {
		data, err := readSpecInput("-")
		require.NoError(t, err)
		assert.Equal(t, "[]", string(data))
	})
}

func TestRunAmendCreateHeadless_FromStdin(t *testing.T) {
	spec := `[{"type":"waiver","requirementId":"AC-1","status":"passed","reason":"x","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}]`
	out := filepath.Join(t.TempDir(), "out.json")
	withStdin(t, spec, func() {
		require.NoError(t, runAmendCreateHeadless("-", out))
	})
	data, _ := os.ReadFile(out) //nolint:gosec // test reads temp file it wrote
	res := validators.ValidateAmendments(data)
	assert.True(t, res.Valid, "stdin headless output must be schema-valid; errors: %v", res.Errors)
}

func TestRunAmendCreateHeadless_InvalidSpec(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "s.json")
	// Missing expiresAt → fatten fails before write.
	require.NoError(t, os.WriteFile(p, []byte(`[{"type":"waiver","requirementId":"AC-1","reason":"x","appliedBy":"a@b.gov"}]`), 0o600))
	err := runAmendCreateHeadless(p, filepath.Join(tmp, "out.json"))
	require.Error(t, err)
}

func TestRunAmendCreateHeadless_Envelope(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "s.json")
	out := filepath.Join(tmp, "out.json")
	spec := `{"name":"Named Doc","overrides":[{"type":"waiver","requirementId":"AC-1","status":"passed","reason":"x","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}]}`
	require.NoError(t, os.WriteFile(p, []byte(spec), 0o600))
	require.NoError(t, runAmendCreateHeadless(p, out))

	data, _ := os.ReadFile(out) //nolint:gosec // test reads temp file it wrote
	var doc map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &doc))
	assert.Equal(t, "Named Doc", doc["name"])
}

func TestRunAmendCreateHeadless_Stdout(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "s.json")
	require.NoError(t, os.WriteFile(p, []byte(`[{"type":"waiver","requirementId":"AC-1","status":"passed","reason":"x","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}]`), 0o600))
	require.NoError(t, runAmendCreateHeadless(p, "")) // outputPath="" → stdout
}

func TestRunAmendCreateHeadless_SchemaValidationFails(t *testing.T) {
	tmp := t.TempDir()
	p := filepath.Join(tmp, "s.json")
	// Fatten succeeds (we don't gate status enum), but an invalid status value
	// must be caught by schema validation before writing.
	require.NoError(t, os.WriteFile(p, []byte(`[{"type":"waiver","requirementId":"AC-1","status":"bogusStatus","reason":"x","appliedBy":"a@b.gov","expiresAt":"2027-01-01"}]`), 0o600))
	err := runAmendCreateHeadless(p, filepath.Join(tmp, "out.json"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schema validation")
}

func TestRunAmendDraft_Stdout(t *testing.T) {
	tmp := t.TempDir()
	rp := filepath.Join(tmp, "r.json")
	require.NoError(t, os.WriteFile(rp, []byte(testResults), 0o600))
	require.NoError(t, runAmendDraft(rp, "waiver", "", "", "1y", "")) // stdout
}

func TestRunAmendDraft_MissingResults(t *testing.T) {
	err := runAmendDraft(filepath.Join(t.TempDir(), "nope.json"), "waiver", "", "", "", "")
	require.Error(t, err)
}

func TestRunAmendDraft_InvalidType(t *testing.T) {
	tmp := t.TempDir()
	rp := filepath.Join(tmp, "r.json")
	require.NoError(t, os.WriteFile(rp, []byte(testResults), 0o600))
	err := runAmendDraft(rp, "bogus", "", "", "", filepath.Join(tmp, "d.json"))
	require.Error(t, err)
}

// --- end-to-end through the cobra command ---

func TestAmendCreateHeadless_E2E(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "spec.json")
	outPath := filepath.Join(tmp, "out.json")
	spec := `[
		{"type":"attestation","requirementId":"SV-1","status":"passed","reason":"reviewed","appliedBy":"assessor@agency.gov","expiresAt":"1y"},
		{"type":"waiver","requirementId":"SV-2","status":"notApplicable","reason":"compensating control","appliedBy":"ao@agency.gov","expiresAt":"2027-02-01"}
	]`
	require.NoError(t, os.WriteFile(specPath, []byte(spec), 0o600))

	err := runAmendCreateHeadless(specPath, outPath)
	require.NoError(t, err)

	out, readErr := os.ReadFile(outPath) //nolint:gosec // test reads temp file it wrote
	require.NoError(t, readErr)
	res := validators.ValidateAmendments(out)
	assert.True(t, res.Valid, "headless E2E output must be schema-valid; errors: %v", res.Errors)
}

func TestAmendDraft_E2E_RejectedByApplyUntilCompleted(t *testing.T) {
	tmp := t.TempDir()
	resultsPath := filepath.Join(tmp, "results.json")
	draftPath := filepath.Join(tmp, "draft.json")
	require.NoError(t, os.WriteFile(resultsPath, []byte(testResults), 0o600))

	err := runAmendDraft(resultsPath, "waiver", "", "", "1y", draftPath)
	require.NoError(t, err)

	draftData, readErr := os.ReadFile(draftPath) //nolint:gosec // test reads temp file it wrote
	require.NoError(t, readErr)

	// apply must refuse a document still marked _draft.
	mergeErr := runAmendApply(nil, resultsPath, draftPath, "")
	require.Error(t, mergeErr, "apply must refuse a draft document")
	assert.Contains(t, mergeErr.Error(), "draft")

	// Once the marker is removed and stubs completed, apply proceeds.
	var draft map[string]interface{}
	require.NoError(t, json.Unmarshal(draftData, &draft))
	delete(draft, "_draft")
	overrides := draft["overrides"].([]interface{})
	stub := overrides[0].(map[string]interface{})
	delete(stub, "_label")
	stub["status"] = "passed"
	stub["reason"] = "risk accepted"
	stub["appliedBy"] = map[string]interface{}{"type": "email", "identifier": "ao@agency.gov"}
	completed, _ := json.Marshal(draft)
	completedPath := filepath.Join(tmp, "completed.json")
	require.NoError(t, os.WriteFile(completedPath, completed, 0o600))

	require.NoError(t, runAmendApply(nil, resultsPath, completedPath, filepath.Join(tmp, "merged.json")))
}
