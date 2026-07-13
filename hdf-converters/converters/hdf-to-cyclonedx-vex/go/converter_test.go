package hdftocyclonedxvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cyclonedxvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/cyclonedx-vex-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testVersion = "test"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tm
}

func loadInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func parseBOM(t *testing.T, b []byte) BOM {
	t.Helper()
	var bom BOM
	require.NoError(t, json.Unmarshal(b, &bom))
	return bom
}

func TestConvertHDFToCycloneDXVEX_NotAffectedExport(t *testing.T) {
	t.Parallel()
	out, err := ConvertHDFToCycloneDXVEX(loadInput(t, "case1-not_affected-amendments.json"), testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)

	assert.Equal(t, "CycloneDX", bom.BOMFormat)
	assert.Equal(t, "1.4", bom.SpecVersion)
	require.Len(t, bom.Vulnerabilities, 1)
	v := bom.Vulnerabilities[0]
	assert.Equal(t, "CVE-2021-44228", v.ID)
	assert.Equal(t, "not_affected", v.Analysis.State)
	assert.Equal(t, "code_not_present", v.Analysis.Justification)
	require.Len(t, v.Affects, 1)
	assert.NotEmpty(t, v.Affects[0].Ref)
}

func TestConvertHDFToCycloneDXVEX_FixedExportProducesOpenExploitable(t *testing.T) {
	t.Parallel()
	// The case1-fixed-amendments fixture is an open POA&M (status=failed,
	// milestone pending). Export MUST emit 'exploitable', not 'resolved' —
	// supplier-claim vs assessed-system invariant.
	out, err := ConvertHDFToCycloneDXVEX(loadInput(t, "case1-fixed-amendments.json"), testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	v := bom.Vulnerabilities[0]
	assert.Equal(t, "exploitable", v.Analysis.State,
		"open POA&M imported from VEX 'fixed' must NOT round-trip to 'resolved'")
	assert.Contains(t, v.Analysis.Response, "workaround_available")
}

func TestConvertHDFToCycloneDXVEX_ClosedPoamExportsAsResolved(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	failed := hdf.Failed
	amendments := hdf.HDFAmendments{
		Name: "Closed POAM",
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.Poam,
			RequirementID: "CVE-2025-1000",
			Status:        &failed,
			AppliedAt:     now,
			ExpiresAt:     exp,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "ops"},
			Reason:        "Vendor patch verified",
			Milestones: []hdf.Milestone{{
				Description:         "Apply 1.2.4",
				Status:              hdf.Completed,
				EstimatedCompletion: exp,
			}},
		}},
	}
	body, _ := json.Marshal(amendments)
	out, err := ConvertHDFToCycloneDXVEX(body, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	assert.Equal(t, "resolved", bom.Vulnerabilities[0].Analysis.State)
	assert.Contains(t, bom.Vulnerabilities[0].Analysis.Response, "update")
}

func TestConvertHDFToCycloneDXVEX_RoundTripPreservesCanonicalFields(t *testing.T) {
	t.Parallel()
	originalCycloneDX, err := os.ReadFile(filepath.Join("..", "..", "cyclonedx-vex-to-hdf",
		"fixtures", "input", "case1-vex-not_affected.json"))
	require.NoError(t, err)

	amendments, err := cyclonedxvex.ConvertCycloneDXVEXToHDF(originalCycloneDX, testVersion)
	require.NoError(t, err)
	hdfBytes, err := json.Marshal(amendments)
	require.NoError(t, err)

	out, err := ConvertHDFToCycloneDXVEX(hdfBytes, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)

	require.Len(t, bom.Vulnerabilities, 1)
	v := bom.Vulnerabilities[0]
	assert.Equal(t, "CVE-2021-44228", v.ID)
	assert.Equal(t, "not_affected", v.Analysis.State)
	assert.Equal(t, "code_not_present", v.Analysis.Justification,
		"canonical justification must survive round-trip")
	require.Len(t, v.Affects, 1)
	// The product@version identifier that csaf-vex import resolved from
	// the BOM's component lookup must propagate to affects[].ref.
	assert.NotEmpty(t, v.Affects[0].Ref)
}

func TestConvertHDFToCycloneDXVEX_EmitsStructuredCycloneDXJustification(t *testing.T) {
	t.Parallel()
	// CycloneDX-specific values (requires_configuration etc.) are part of
	// the HDF Justification enum (v3.2.x extension); the export uses the
	// structured field directly.
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	just := hdf.RequiresConfiguration
	amendments := hdf.HDFAmendments{
		Name: "Structured",
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.FalsePositive,
			RequirementID: "CVE-2026-1234",
			Status:        &passed,
			AppliedAt:     now,
			ExpiresAt:     exp,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "team"},
			Justification: &just,
			Reason:        "Configuration prevents the issue.\nProducts: pkg:npm/x@1.0",
		}},
	}
	body, _ := json.Marshal(amendments)
	out, err := ConvertHDFToCycloneDXVEX(body, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	assert.Equal(t, "requires_configuration", bom.Vulnerabilities[0].Analysis.Justification)
}

func TestConvertHDFToCycloneDXVEX_NonCVEOverridesAreSkipped(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "Mixed",
		Overrides: []hdf.StandaloneOverride{
			{Type: hdf.FalsePositive, RequirementID: "AC-2", Status: &passed, AppliedAt: now, ExpiresAt: exp, AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"}, Reason: "policy"},
			{Type: hdf.FalsePositive, RequirementID: "CVE-2024-99999", Status: &passed, AppliedAt: now, ExpiresAt: exp, AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"}, Reason: "not affected"},
		},
	}
	body, _ := json.Marshal(amendments)
	out, err := ConvertHDFToCycloneDXVEX(body, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2024-99999", bom.Vulnerabilities[0].ID)
}

func TestConvertHDFToCycloneDXVEX_ErrorsOnNoCVEOverrides(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "No CVE",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Attestation, RequirementID: "NIST-AC-1", Status: &passed,
			AppliedAt: now, ExpiresAt: exp,
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"},
			Reason:    "manual",
		}},
	}
	body, _ := json.Marshal(amendments)
	_, err := ConvertHDFToCycloneDXVEX(body, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no overrides with CVE-shaped requirementIds")
}

func TestConvertHDFToCycloneDXVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCycloneDXVEX([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertHDFToCycloneDXVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCycloneDXVEX(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestProductIDsFor_PrefersComponentRef(t *testing.T) {
	t.Parallel()
	ref := "pkg:npm/foo@1.2.3"
	got := productIDsFor(&hdf.StandaloneOverride{ComponentRef: &ref, Reason: "Products: IGNORED"})
	assert.Equal(t, []string{ref}, got)
}

func TestProductIDsFor_ParsesProductsLine(t *testing.T) {
	t.Parallel()
	got := productIDsFor(&hdf.StandaloneOverride{Reason: "prose\nProducts: A, B"})
	assert.Equal(t, []string{"A", "B"}, got)
}

func TestProductIDsFor_FallsBackToDefault(t *testing.T) {
	t.Parallel()
	got := productIDsFor(&hdf.StandaloneOverride{Reason: "no products"})
	assert.Equal(t, []string{defaultProductID}, got)
}

func TestStripReasonAnnotations(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "prose", stripReasonAnnotations("prose\nProducts: A\nVEX justification: code_not_present\nResponse: update"))
	assert.Equal(t, "only prose", stripReasonAnnotations("only prose"))
	assert.Equal(t, "", stripReasonAnnotations("Products: A"))
}

func TestAllMilestonesCompleted(t *testing.T) {
	t.Parallel()
	assert.False(t, allMilestonesCompleted(&hdf.StandaloneOverride{}), "empty milestones = not completed")
	assert.False(t, allMilestonesCompleted(&hdf.StandaloneOverride{Milestones: []hdf.Milestone{{Status: hdf.Pending}}}))
	assert.True(t, allMilestonesCompleted(&hdf.StandaloneOverride{Milestones: []hdf.Milestone{{Status: hdf.Completed}, {Status: hdf.Completed}}}))
	assert.False(t, allMilestonesCompleted(&hdf.StandaloneOverride{Milestones: []hdf.Milestone{{Status: hdf.Completed}, {Status: hdf.Pending}}}))
}

func TestConvertHDFToCycloneDXVEX_CvssRating(t *testing.T) {
	input := []byte(`{"overrides":[{
		"type":"falsePositive","requirementId":"CVE-2021-44228","status":"notApplicable","reason":"nr",
		"componentRef":"pkg:maven/log4j@2.14.1",
		"appliedBy":{"type":"simple","identifier":"a"},"appliedAt":"2026-01-01T00:00:00Z",
		"cvss":{"version":"3.1","baseVector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":10,"baseSeverity":"critical"}
	}]}`)
	out, err := ConvertHDFToCycloneDXVEX(input, testVersion)
	require.NoError(t, err)
	var bom BOM
	require.NoError(t, json.Unmarshal(out, &bom))
	require.Len(t, bom.Vulnerabilities, 1)
	r := bom.Vulnerabilities[0].Ratings
	require.NotEmpty(t, r)
	require.NotNil(t, r[0].Score)
	assert.InDelta(t, 10.0, *r[0].Score, 0.001)
	assert.Equal(t, "CVSSv31", r[0].Method)
	assert.Contains(t, r[0].Vector, "CVSS:3.1")
	assert.Equal(t, "critical", r[0].Severity)
}

func TestConvertHDFToCycloneDXVEX_FixedInVersionEmitsVersRange(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"name": "fixedInVersion",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-7777",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"reason": "patched upstream",
			"affectedPackages": [{"name": "abc", "version": "4.2", "purl": "pkg:npm/abc@4.2", "fixedInVersion": "4.5"}]
		}]
	}`)
	out, err := ConvertHDFToCycloneDXVEX(input, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	affects := bom.Vulnerabilities[0].Affects
	require.Len(t, affects, 1)
	require.Len(t, affects[0].Versions, 2)
	assert.Equal(t, CdxVersion{Version: "4.2", Status: "affected"}, affects[0].Versions[0])
	assert.Equal(t, CdxVersion{Range: "vers:npm/>=4.5", Status: "unaffected"}, affects[0].Versions[1])
	assert.Empty(t, bom.Vulnerabilities[0].Recommendation)
}

func TestConvertHDFToCycloneDXVEX_FixedInVersionFallsBackToRecommendation(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"name": "fixedInVersion",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-8888",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"reason": "patched upstream",
			"affectedPackages": [{"cpe": "cpe:2.3:a:acme:abc:4.2:*:*:*:*:*:*:*", "fixedInVersion": "4.5"}]
		}]
	}`)
	out, err := ConvertHDFToCycloneDXVEX(input, testVersion)
	require.NoError(t, err)
	bom := parseBOM(t, out)
	require.Len(t, bom.Vulnerabilities, 1)
	assert.Equal(t, "Upgrade to 4.5", bom.Vulnerabilities[0].Recommendation)
	assert.Empty(t, bom.Vulnerabilities[0].Affects[0].Versions)
}

// TestGoldenParity asserts byte-for-byte output against frozen golden files.
// The TypeScript test asserts against the SAME files, guaranteeing TS↔Go parity.
func TestGoldenParity(t *testing.T) {
	cases := map[string]string{
		"case1-fixed-amendments":        "case1-fixed.cdx.json",
		"case1-not_affected-amendments": "case1-not_affected.cdx.json",
	}
	for input, goldenName := range cases {
		out, err := ConvertHDFToCycloneDXVEX(loadInput(t, input+".json"), testVersion)
		require.NoError(t, err)
		goldenPath := filepath.Join("..", "fixtures", "expected", goldenName)
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, string(golden), string(out), "golden mismatch for %s", input)
	}
}
