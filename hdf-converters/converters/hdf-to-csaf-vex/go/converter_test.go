package hdftocsafvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	csafvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/csaf-vex-to-hdf/go"
	fixtures "github.com/mitre/hdf-libs/hdf-fixtures"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return tm
}

const testVersion = "test"

// uc-01-fixed-amendments.json lives in the shared corpus (hdf-to-oscal-poam
// consumes it too); the other inputs are local to this converter.
func loadInput(t *testing.T, name string) []byte {
	t.Helper()
	if name == "uc-01-fixed-amendments.json" {
		return fixtures.Amendments.UC01Fixed
	}
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

func TestConvertHDFToCSAFVEX_KnownNotAffectedExport(t *testing.T) {
	t.Parallel()
	out, err := ConvertHDFToCSAFVEX(loadInput(t, "sec-vex-amendments.json"), testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))

	assert.Equal(t, "csaf_vex", doc.Document.Category)
	assert.Equal(t, "2.0", doc.Document.CSAFVersion)
	require.Len(t, doc.Vulnerabilities, 3, "three CVEs from the secvisogram fixture")

	for _, v := range doc.Vulnerabilities {
		require.NotNil(t, v.ProductStatus)
		assert.NotEmpty(t, v.ProductStatus.KnownNotAffected, "all three should land in known_not_affected")
		require.Len(t, v.Flags, 1, "each should carry the justification flag round-tripped")
		assert.Equal(t, "component_not_present", v.Flags[0].Label)
	}
}

func TestConvertHDFToCSAFVEX_FixedExportProducesOpenPoamAsAffected(t *testing.T) {
	t.Parallel()
	// uc-01-fixed-amendments.json was imported as a POA&M pinned to 'failed'
	// with a pending milestone. Without closure, the export must treat the
	// POA&M as still-affected (not 'fixed') — supplier-claim vs real-system.
	out, err := ConvertHDFToCSAFVEX(loadInput(t, "uc-01-fixed-amendments.json"), testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	v := doc.Vulnerabilities[0]
	require.NotNil(t, v.ProductStatus)
	assert.Empty(t, v.ProductStatus.Fixed,
		"open POA&M (milestone pending) must NOT emit as 'fixed' on export")
	assert.NotEmpty(t, v.ProductStatus.KnownAffected,
		"open POA&M from VEX 'fixed' is still 'known_affected' to the assessed system")
	assert.NotEmpty(t, v.Remediations, "milestone description surfaces as a remediation")
}

func TestConvertHDFToCSAFVEX_RoundTripPreservesCanonicalFields(t *testing.T) {
	t.Parallel()
	// Round-trip: CSAF VEX -> HDF Amendments -> CSAF VEX. The CVE id,
	// status bucket (known_not_affected), and justification flag are the
	// canonical consumer-action payload — they MUST survive untouched.
	csafInput, err := os.ReadFile(filepath.Join("..", "..", "csaf-vex-to-hdf",
		"fixtures", "input", "sec-vex-2022-0001.json"))
	require.NoError(t, err)

	amendments, err := csafvex.ConvertCSAFVEXToHDF(csafInput, testVersion)
	require.NoError(t, err)
	hdfBytes, err := json.Marshal(amendments)
	require.NoError(t, err)

	csafOutput, err := ConvertHDFToCSAFVEX(hdfBytes, testVersion)
	require.NoError(t, err)

	var roundTripped CSAFVexDocument
	require.NoError(t, json.Unmarshal(csafOutput, &roundTripped))

	originalCVEs := []string{"CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"}
	require.Len(t, roundTripped.Vulnerabilities, len(originalCVEs))
	for i, v := range roundTripped.Vulnerabilities {
		assert.Equal(t, originalCVEs[i], v.CVE)
		require.NotNil(t, v.ProductStatus)
		assert.NotEmpty(t, v.ProductStatus.KnownNotAffected,
			"not_affected status must survive round-trip")
		require.Len(t, v.Flags, 1, "justification flag must survive round-trip")
		assert.Equal(t, "component_not_present", v.Flags[0].Label)
	}
}

func TestConvertHDFToCSAFVEX_NonCVEOverridesAreSkipped(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "Mixed amendments",
		Overrides: []hdf.StandaloneOverride{
			{
				Type:          hdf.FalsePositive,
				RequirementID: "AC-2", // non-CVE; must be skipped
				Status:        &passed,
				AppliedAt:     now,
				ExpiresAt:     exp,
				AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "alice"},
				Reason:        "compensating control",
			},
			{
				Type:          hdf.FalsePositive,
				RequirementID: "CVE-2024-99999",
				Status:        &passed,
				AppliedAt:     now,
				ExpiresAt:     exp,
				AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "alice"},
				Reason:        "not affected",
			},
		},
	}
	body, err := json.Marshal(amendments)
	require.NoError(t, err)

	out, err := ConvertHDFToCSAFVEX(body, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1, "only the CVE-shaped requirementId survives")
	assert.Equal(t, "CVE-2024-99999", doc.Vulnerabilities[0].CVE)
}

func TestConvertHDFToCSAFVEX_ErrorsOnNoCVEOverrides(t *testing.T) {
	t.Parallel()
	now := mustTime(t, "2026-01-01T00:00:00Z")
	exp := mustTime(t, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "No CVE amendments",
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.Attestation,
			RequirementID: "AC-1",
			Status:        &passed,
			AppliedAt:     now,
			ExpiresAt:     exp,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "x"},
			Reason:        "manual review",
		}},
	}
	body, err := json.Marshal(amendments)
	require.NoError(t, err)
	_, err = ConvertHDFToCSAFVEX(body, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no overrides with CVE-shaped requirementIds")
}

func TestConvertHDFToCSAFVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCSAFVEX([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertHDFToCSAFVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToCSAFVEX(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestProductIDsFor_PrefersComponentRef(t *testing.T) {
	t.Parallel()
	ref := "MY-COMPONENT-UUID"
	o := &hdf.StandaloneOverride{ComponentRef: &ref, Reason: "Products: IGNORED"}
	assert.Equal(t, []string{"MY-COMPONENT-UUID"}, productIDsFor(o))
}

func TestProductIDsFor_ParsesReasonLine(t *testing.T) {
	t.Parallel()
	o := &hdf.StandaloneOverride{Reason: "lots of prose\nProducts: CSAFPID-1, CSAFPID-2"}
	assert.Equal(t, []string{"CSAFPID-1", "CSAFPID-2"}, productIDsFor(o))
}

func TestProductIDsFor_FallsBackToDefault(t *testing.T) {
	t.Parallel()
	o := &hdf.StandaloneOverride{Reason: "no products line here"}
	assert.Equal(t, []string{defaultProductID}, productIDsFor(o))
}

func TestStripProductsLineRemovesTail(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "prose", stripProductsLine("prose\nProducts: A, B"))
	assert.Equal(t, "only prose", stripProductsLine("only prose"))
}

func TestConvertHDFToCSAFVEX_CvssScore(t *testing.T) {
	t.Parallel()
	input := []byte(`{"overrides":[{
		"type":"falsePositive","requirementId":"CVE-2021-44228","status":"notApplicable","reason":"not reachable",
		"componentRef":"pkg:maven/log4j@2.14.1",
		"appliedBy":{"type":"simple","identifier":"a"},"appliedAt":"2026-01-01T00:00:00Z",
		"cvss":{"version":"3.1","baseVector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":10,"baseSeverity":"critical"}
	}]}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	v := doc.Vulnerabilities[0]
	require.NotEmpty(t, v.Scores)
	require.NotNil(t, v.Scores[0].CvssV3)
	assert.Equal(t, "3.1", v.Scores[0].CvssV3.Version)
	require.NotNil(t, v.Scores[0].CvssV3.BaseScore)
	assert.InDelta(t, 10.0, *v.Scores[0].CvssV3.BaseScore, 0.001)
	assert.Contains(t, v.Scores[0].CvssV3.VectorString, "CVSS:3.1")
	assert.NotEmpty(t, v.Scores[0].Products)
}

func TestConvertHDFToCSAFVEX_FixedInVersionExport(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"name": "fixedInVersion",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-9999",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"reason": "patched upstream",
			"affectedPackages": [{"name": "abc", "version": "4.2", "purl": "pkg:npm/abc@4.2", "fixedInVersion": "4.5"}]
		}]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	v := doc.Vulnerabilities[0]
	require.NotNil(t, v.ProductStatus)
	assert.Contains(t, v.ProductStatus.FirstFixed, "pkg:npm/abc@4.5")
	assert.Contains(t, v.ProductStatus.Fixed, "pkg:npm/abc@4.5")

	var found bool
	for _, r := range v.Remediations {
		if r.Category == "vendor_fix" && r.Details == "Fixed in 4.5" {
			assert.Equal(t, []string{"pkg:npm/abc@4.5"}, r.ProductIDs)
			found = true
		}
	}
	assert.True(t, found, "expected a vendor_fix remediation for the fixed version")

	var ids []string
	for _, p := range doc.ProductTree.FullProductNames {
		ids = append(ids, p.ProductID)
	}
	assert.Contains(t, ids, "pkg:npm/abc@4.5")
}

func TestConvertHDFToCSAFVEX_ProductTreeGloballySorted(t *testing.T) {
	t.Parallel()
	// product_tree ids must be globally sorted (parity with the TS exporter),
	// even when alphabetical order differs from CVE/group insertion order.
	input := []byte(`{
		"name": "ordering",
		"overrides": [
			{"type":"falsePositive","requirementId":"CVE-2026-0001","status":"passed","appliedAt":"2026-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z","appliedBy":{"type":"simple","identifier":"team"},"reason":"x","affectedPackages":[{"purl":"pkg:npm/zzz@1.0"}]},
			{"type":"falsePositive","requirementId":"CVE-2026-0002","status":"passed","appliedAt":"2026-01-01T00:00:00Z","expiresAt":"2099-12-31T00:00:00Z","appliedBy":{"type":"simple","identifier":"team"},"reason":"x","affectedPackages":[{"purl":"pkg:npm/aaa@1.0"}]}
		]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	var ids []string
	for _, p := range doc.ProductTree.FullProductNames {
		ids = append(ids, p.ProductID)
	}
	assert.Equal(t, []string{"pkg:npm/aaa@1.0", "pkg:npm/zzz@1.0"}, ids)
}

func TestConvertHDFToCSAFVEX_ReasonNoteOnNotAffected(t *testing.T) {
	t.Parallel()
	// A not_affected (falsePositive) override's reason prose must be surfaced
	// as a CSAF description note — previously it was dropped (only the affected
	// path kept reason, as threats[impact]).
	out, err := ConvertHDFToCSAFVEX(loadInput(t, "sec-vex-amendments.json"), testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 3)
	for _, v := range doc.Vulnerabilities {
		require.Len(t, v.Notes, 1, "reason must surface as a description note")
		assert.Equal(t, "description", v.Notes[0].Category)
		assert.NotEmpty(t, v.Notes[0].Text)
	}
}

func TestConvertHDFToCSAFVEX_ProductIdentificationHelperRoundTrip(t *testing.T) {
	t.Parallel()
	// A purl affectedPackage must emit product_identification_helper.purl so
	// csaf-vex-to-hdf can resolve the product back to a structured
	// AffectedPackage — restoring the previously severed package identity.
	const purl = "pkg:npm/left-pad@1.3.0"
	input := []byte(`{
		"name": "purl round-trip",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-7777",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"justification": "component_not_present",
			"reason": "left-pad is not bundled",
			"affectedPackages": [{"name": "left-pad", "version": "1.3.0", "ecosystem": "npm", "purl": "` + purl + `"}]
		}]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)

	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.ProductTree.FullProductNames, 1)
	fpn := doc.ProductTree.FullProductNames[0]
	assert.Equal(t, purl, fpn.ProductID)
	require.NotNil(t, fpn.ProductIdentificationHelper, "purl package must emit a helper")
	assert.Equal(t, purl, fpn.ProductIdentificationHelper.Purl)

	// Round-trip: re-import restores the AffectedPackage purl.
	amendments, err := csafvex.ConvertCSAFVEXToHDF(out, testVersion)
	require.NoError(t, err)
	require.Len(t, amendments.Overrides, 1)
	require.Len(t, amendments.Overrides[0].AffectedPackages, 1)
	require.NotNil(t, amendments.Overrides[0].AffectedPackages[0].Purl)
	assert.Equal(t, purl, *amendments.Overrides[0].AffectedPackages[0].Purl)
}

func TestConvertHDFToCSAFVEX_CpeIdentificationHelper(t *testing.T) {
	t.Parallel()
	const cpe = "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
	input := []byte(`{
		"name": "cpe helper",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-8888",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"justification": "component_not_present",
			"reason": "not affected",
			"affectedPackages": [{"cpe": "` + cpe + `"}]
		}]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.ProductTree.FullProductNames, 1)
	require.NotNil(t, doc.ProductTree.FullProductNames[0].ProductIdentificationHelper)
	assert.Equal(t, cpe, doc.ProductTree.FullProductNames[0].ProductIdentificationHelper.CPE)
}

func TestConvertHDFToCSAFVEX_ExternalReferencesExport(t *testing.T) {
	t.Parallel()
	// externalReferences[].href must surface as references[category=external],
	// alongside url evidence.
	input := []byte(`{
		"name": "external refs",
		"overrides": [{
			"type": "falsePositive",
			"requirementId": "CVE-2026-6666",
			"status": "passed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "team"},
			"justification": "component_not_present",
			"reason": "not affected",
			"externalReferences": [
				{"sourceName": "stix", "href": "https://cti.example.com/indicator/42", "description": "STIX indicator"},
				{"sourceName": "cve", "externalId": "CVE-2026-6666"}
			]
		}]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	var found bool
	for _, r := range doc.Vulnerabilities[0].References {
		if r.URL == "https://cti.example.com/indicator/42" {
			assert.Equal(t, "external", r.Category)
			assert.Equal(t, "STIX indicator", r.Summary)
			found = true
		}
	}
	assert.True(t, found, "externalReferences href must surface as a reference")
	assert.Len(t, doc.Vulnerabilities[0].References, 1, "the href-less external reference is skipped")
}

func TestConvertHDFToCSAFVEX_MilestoneDateExport(t *testing.T) {
	t.Parallel()
	// completedAt takes precedence over estimatedCompletion for the CSAF
	// remediation date.
	input := []byte(`{
		"name": "milestone dates",
		"overrides": [{
			"type": "poam",
			"requirementId": "CVE-2026-5555",
			"status": "failed",
			"appliedAt": "2026-01-01T00:00:00Z",
			"expiresAt": "2099-12-31T00:00:00Z",
			"appliedBy": {"type": "simple", "identifier": "ops"},
			"reason": "tracking",
			"milestones": [{"description": "apply patch", "status": "completed", "estimatedCompletion": "2026-02-01T00:00:00Z", "completedAt": "2026-03-15T00:00:00Z"}]
		}]
	}`)
	out, err := ConvertHDFToCSAFVEX(input, testVersion)
	require.NoError(t, err)
	var doc CSAFVexDocument
	require.NoError(t, json.Unmarshal(out, &doc))
	require.Len(t, doc.Vulnerabilities, 1)
	require.NotEmpty(t, doc.Vulnerabilities[0].Remediations)
	assert.Equal(t, "2026-03-15T00:00:00Z", doc.Vulnerabilities[0].Remediations[0].Date)
}

// TestGoldenParity asserts byte-for-byte output against frozen golden files.
// The TypeScript test asserts against the SAME files, guaranteeing TS↔Go parity.
func TestGoldenParity(t *testing.T) {
	for _, name := range []string{"sec-vex-amendments", "uc-01-fixed-amendments"} {
		out, err := ConvertHDFToCSAFVEX(loadInput(t, name+".json"), testVersion)
		require.NoError(t, err)
		goldenPath := filepath.Join("..", "fixtures", "expected", name+".csaf-vex.json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, string(golden), string(out), "golden mismatch for %s", name)
	}
}
