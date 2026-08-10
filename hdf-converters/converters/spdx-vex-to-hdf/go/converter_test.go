package spdxvex

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

const testVersion = "test"

func loadInput(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "fixtures", "input", name))
	require.NoError(t, err)
	return data
}

// findOverride returns the override with the given requirementId, or fails.
func findOverride(t *testing.T, result *hdf.HDFAmendments, cve string) hdf.StandaloneOverride {
	t.Helper()
	for _, o := range result.Overrides {
		if o.RequirementID == cve {
			return o
		}
	}
	t.Fatalf("no override for %s", cve)
	return hdf.StandaloneOverride{}
}

func TestConvertSPDXVEX_SampleShapeAndOverrideCount(t *testing.T) {
	t.Parallel()
	result, err := ConvertSPDXVEXToHDF(loadInput(t, "sample.spdx.json"), testVersion)
	require.NoError(t, err)
	require.NotNil(t, result)

	// HDFAmendments envelope.
	assert.Equal(t, "SPDX VEX statements from sbom-cve-check", result.Name)
	require.NotNil(t, result.Generator)
	assert.Equal(t, "spdx-vex-to-hdf", result.Generator.Name)
	assert.Equal(t, testVersion, result.Generator.Version)
	require.NotNil(t, result.AppliedBy)
	assert.Equal(t, "sbom-cve-check", result.AppliedBy.Identifier)
	assert.Equal(t, hdf.IdentityTypeSystem, result.AppliedBy.Type)
	require.NotNil(t, result.Integrity)

	// Exactly 2 overrides: not_affected (CVE-30002) and fixed (CVE-30003).
	// affected (CVE-30001) and under_investigation (CVE-30004) are skipped.
	require.Len(t, result.Overrides, 2)
	cves := []string{result.Overrides[0].RequirementID, result.Overrides[1].RequirementID}
	assert.ElementsMatch(t, []string{"CVE-2024-30002", "CVE-2024-30003"}, cves)
	assert.NotContains(t, cves, "CVE-2024-30001", "affected is skipped")
	assert.NotContains(t, cves, "CVE-2024-30004", "under_investigation is skipped")

	body, _ := json.Marshal(result)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments output must validate: %s", v.Error())
}

func TestConvertSPDXVEX_NotAffectedOverride(t *testing.T) {
	t.Parallel()
	result, err := ConvertSPDXVEXToHDF(loadInput(t, "sample.spdx.json"), testVersion)
	require.NoError(t, err)

	o := findOverride(t, result, "CVE-2024-30002")
	assert.Equal(t, hdf.FalsePositive, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Passed, *o.Status)
	require.NotNil(t, o.Justification)
	assert.Equal(t, hdf.VulnerableCodeNotInExecutePath, *o.Justification,
		"SPDX camelCase vulnerableCodeNotInExecutePath normalizes to the HDF enum")

	// Reason joins vuln.description + impactStatement + statusNotes.
	assert.Contains(t, o.Reason, "not_affected VEX assessment")
	assert.Contains(t, o.Reason, "not reachable in the shipped configuration")
	assert.Contains(t, o.Reason, "Reviewed by examplevendor security team")

	// AffectedPackages resolved from the `to` package's cpe23.
	require.Len(t, o.AffectedPackages, 1)
	require.NotNil(t, o.AffectedPackages[0].Cpe)
	assert.Equal(t, "cpe:2.3:a:examplevendor:example-lib:1.0.0:*:*:*:*:*:*:*", *o.AffectedPackages[0].Cpe)

	// AppliedAt from CreationInfo1; ExpiresAt = +365d. AppliedBy from agent.
	assert.Equal(t, "2026-08-10T16:39:41Z", o.AppliedAt.UTC().Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "2027-08-10T16:39:41Z", o.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	assert.Equal(t, "sbom-cve-check", o.AppliedBy.Identifier)

	// Evidence carries the CVE identifierLocator URLs.
	require.NotEmpty(t, o.Evidence)
	assert.Equal(t, hdf.URL, o.Evidence[0].Type)

	// The committed fixture's only CVSS relationship is on the AFFECTED CVE
	// (30001), which is skipped, so no override carries CVSS here.
	assert.Nil(t, o.Cvss, "sample fixture's CVSS is on the affected (skipped) CVE")
}

func TestConvertSPDXVEX_FixedOverride(t *testing.T) {
	t.Parallel()
	result, err := ConvertSPDXVEXToHDF(loadInput(t, "sample.spdx.json"), testVersion)
	require.NoError(t, err)

	o := findOverride(t, result, "CVE-2024-30003")
	assert.Equal(t, hdf.Poam, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Failed, *o.Status, "VEX fixed is an open POA&M pinned to failed (never flip to passed)")
	assert.Nil(t, o.Justification, "fixed carries no justification")
	require.Len(t, o.Milestones, 1)
	assert.Equal(t, hdf.Pending, o.Milestones[0].Status)
	assert.NotEmpty(t, o.Milestones[0].Description)
	assert.Contains(t, o.Reason, "Patched in the 2.3.1 build")

	require.Len(t, o.AffectedPackages, 1)
	require.NotNil(t, o.AffectedPackages[0].Cpe)
	assert.Equal(t, "cpe:2.3:a:examplevendor:sample-utils:2.3.1:*:*:*:*:*:*:*", *o.AffectedPackages[0].Cpe)
}

// The committed fixture cannot exercise CVSS -> override.Cvss because its only
// CVSS relationship is on the AFFECTED (skipped) CVE. This focused test uses a
// hand-built minimal SPDX-3 snippet where a not_affected CVE also carries a
// CvssV3 relationship, so the mapping is covered.
func TestConvertSPDXVEX_CvssMappedOntoActionableOverride(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"type": "CreationInfo", "@id": "_:C1", "created": "2026-01-01T00:00:00Z", "createdBy": ["agent-1"]},
			{"type": "SoftwareAgent", "spdxId": "agent-1", "name": "scanner"},
			{"type": "software_Package", "spdxId": "pkg-1", "name": "libx",
			 "externalIdentifier": [{"externalIdentifierType": "cpe23", "identifier": "cpe:2.3:a:v:libx:1.0:*:*:*:*:*:*:*"}]},
			{"type": "security_Vulnerability", "spdxId": "vuln-1", "creationInfo": "_:C1",
			 "description": "desc",
			 "externalIdentifier": [{"externalIdentifierType": "cve", "identifier": "CVE-2026-9999"}]},
			{"type": "security_CvssV3VulnAssessmentRelationship", "from": "vuln-1", "to": ["pkg-1"],
			 "security_score": "7.5", "security_severity": "high",
			 "security_vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "creationInfo": "_:C1"},
			{"type": "security_VexNotAffectedVulnAssessmentRelationship", "from": "vuln-1", "to": ["pkg-1"],
			 "security_justificationType": "vulnerableCodeNotInExecutePath",
			 "security_statusNotes": "not reachable", "creationInfo": "_:C1"}
		]
	}`)
	result, err := ConvertSPDXVEXToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)
	o := result.Overrides[0]
	require.NotNil(t, o.Cvss)
	require.NotNil(t, o.Cvss.BaseScore)
	assert.InDelta(t, 7.5, *o.Cvss.BaseScore, 0.001)
	require.NotNil(t, o.Cvss.BaseVector)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", *o.Cvss.BaseVector)
	require.NotNil(t, o.Cvss.BaseSeverity)
	assert.Equal(t, hdf.CVSSSeverityHigh, *o.Cvss.BaseSeverity)
	assert.Equal(t, hdf.The31, o.Cvss.Version)
	require.NotNil(t, o.Cvss.Source)
	assert.Equal(t, "CVE-2026-9999", *o.Cvss.Source)

	body, _ := json.Marshal(result)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments output must validate: %s", v.Error())
}

func TestConvertSPDXVEX_NoActionableStatementsErrors(t *testing.T) {
	t.Parallel()
	_, err := ConvertSPDXVEXToHDF(loadInput(t, "no-actionable.spdx.json"), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no actionable VEX statements")
}

func TestConvertSPDXVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertSPDXVEXToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertSPDXVEX_RejectsEmptyGraph(t *testing.T) {
	t.Parallel()
	_, err := ConvertSPDXVEXToHDF([]byte(`{"@context": "x", "@graph": []}`), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "@graph")
}

func TestConvertSPDXVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertSPDXVEXToHDF(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestCvssVersion(t *testing.T) {
	t.Parallel()
	assert.Equal(t, hdf.The31, cvssVersion("security_CvssV3VulnAssessmentRelationship", "CVSS:3.1/AV:N"))
	assert.Equal(t, hdf.The30, cvssVersion("security_CvssV3VulnAssessmentRelationship", "CVSS:3.0/AV:N"))
	assert.Equal(t, hdf.The40, cvssVersion("security_CvssV4VulnAssessmentRelationship", "CVSS:4.0/AV:N"))
	// Falls back to the relationship subtype when the vector has no version prefix.
	assert.Equal(t, hdf.The20, cvssVersion("security_CvssV2VulnAssessmentRelationship", "AV:N/AC:L"))
	assert.Equal(t, hdf.The40, cvssVersion("security_CvssV4VulnAssessmentRelationship", ""))
	assert.Equal(t, hdf.The31, cvssVersion("security_CvssV3VulnAssessmentRelationship", ""))
}

func TestCvssSeverity(t *testing.T) {
	t.Parallel()
	assert.Equal(t, hdf.CVSSSeverityCritical, cvssSeverity("critical"))
	assert.Equal(t, hdf.CVSSSeverityHigh, cvssSeverity(" HIGH "))
	assert.Equal(t, hdf.None, cvssSeverity("none"))
	assert.Equal(t, hdf.CVSSSeverity(""), cvssSeverity("bogus"))
}

func TestPackageIdentifier_PrefersPurl(t *testing.T) {
	t.Parallel()
	pkg := &graphElement{ExternalIDs: []externalIdentifier{
		{ExternalIdentifierType: "cpe23", Identifier: "cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"},
		{ExternalIdentifierType: "purl", Identifier: "pkg:generic/x@1.0"},
	}}
	assert.Equal(t, "pkg:generic/x@1.0", packageIdentifier(pkg))

	cpeOnly := &graphElement{ExternalIDs: []externalIdentifier{
		{ExternalIdentifierType: "cpe23", Identifier: "cpe:2.3:a:v:x:1:*:*:*:*:*:*:*"},
	}}
	assert.Equal(t, "cpe:2.3:a:v:x:1:*:*:*:*:*:*:*", packageIdentifier(cpeOnly))

	assert.Equal(t, "", packageIdentifier(&graphElement{}))
}

// TestSnapshots asserts the fixtures/expected/<input>.hdf.json golden reproduces
// whole-output, enforcing TS<->Go structural parity on the amendment document.
func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "spdx-vex-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertSPDXVEXToHDF(input, "1.0.0")
	})
}
