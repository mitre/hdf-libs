package hdftoopenvex

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	openvex "github.com/mitre/hdf-libs/hdf-converters/v3/converters/openvex-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
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

func parseDoc(t *testing.T, b []byte) Document {
	t.Helper()
	var d Document
	require.NoError(t, json.Unmarshal(b, &d))
	return d
}

func TestConvertHDFToOpenVEX_NotAffectedExport(t *testing.T) {
	t.Parallel()
	out, err := ConvertHDFToOpenVEX(loadInput(t, "spring-boot-log4j-amendments.json"), testVersion)
	require.NoError(t, err)
	doc := parseDoc(t, out)

	assert.Equal(t, openvexContext, doc.Context)
	require.Len(t, doc.Statements, 1)
	s := doc.Statements[0]
	assert.Equal(t, "CVE-2021-44228", s.Vulnerability.Name)
	assert.Equal(t, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", s.Vulnerability.ID)
	assert.Equal(t, "not_affected", s.Status)
	assert.Equal(t, "vulnerable_code_not_in_execute_path", s.Justification)
	assert.Contains(t, s.ImpactStatement, "Spring Boot users")
	require.Len(t, s.Products, 1)
	assert.Equal(t, "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3", s.Products[0].ID)
}

func TestConvertHDFToOpenVEX_MultiStatusExport(t *testing.T) {
	t.Parallel()
	out, err := ConvertHDFToOpenVEX(loadInput(t, "multi-status-amendments.json"), testVersion)
	require.NoError(t, err)
	doc := parseDoc(t, out)

	byCVE := map[string]Statement{}
	for _, s := range doc.Statements {
		byCVE[s.Vulnerability.Name] = s
	}

	na, ok := byCVE["CVE-2024-1000"]
	require.True(t, ok)
	assert.Equal(t, "not_affected", na.Status)
	assert.Equal(t, "component_not_present", na.Justification)

	fixed, ok := byCVE["CVE-2024-2000"]
	require.True(t, ok)
	// VEX 'fixed' on import becomes an open POA&M; export stays affected
	// without closure confirmation.
	assert.Equal(t, "affected", fixed.Status, "open POA&M from VEX 'fixed' stays 'affected' on export")
	assert.Contains(t, fixed.ActionStatement, "vendor reports fix")
}

func TestConvertHDFToOpenVEX_RoundTripPreservesCanonicalFields(t *testing.T) {
	t.Parallel()
	originalCSAF, err := os.ReadFile(filepath.Join("..", "..", "openvex-to-hdf",
		"fixtures", "input", "spring-boot-log4j.openvex.json"))
	require.NoError(t, err)

	amendments, err := openvex.ConvertOpenVEXToHDF(originalCSAF, testVersion)
	require.NoError(t, err)
	hdfBytes, err := json.Marshal(amendments)
	require.NoError(t, err)

	out, err := ConvertHDFToOpenVEX(hdfBytes, testVersion)
	require.NoError(t, err)
	doc := parseDoc(t, out)

	require.Len(t, doc.Statements, 1)
	s := doc.Statements[0]
	assert.Equal(t, "CVE-2021-44228", s.Vulnerability.Name)
	assert.Equal(t, "not_affected", s.Status)
	assert.Equal(t, "vulnerable_code_not_in_execute_path", s.Justification,
		"justification enum is the canonical consumer-action payload and MUST round-trip")
	require.Len(t, s.Products, 1)
	assert.Equal(t, "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3", s.Products[0].ID,
		"product PURL parsed back from the reason's Products: line")
}

func TestConvertHDFToOpenVEX_ClosedPoamExportsAsFixed(t *testing.T) {
	t.Parallel()
	now, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	exp, _ := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	failed := hdf.Failed
	amendments := hdf.HDFAmendments{
		Name: "Closed",
		Overrides: []hdf.StandaloneOverride{{
			Type:          hdf.Poam,
			RequirementID: "CVE-2025-1000",
			Status:        &failed,
			AppliedAt:     now,
			ExpiresAt:     exp,
			AppliedBy:     hdf.Identity{Type: hdf.Simple, Identifier: "ops"},
			Reason:        "Vendor patch applied and verified.",
			Milestones: []hdf.Milestone{{
				Description:         "Apply 1.2.4",
				Status:              hdf.Completed,
				EstimatedCompletion: exp,
			}},
		}},
	}
	body, _ := json.Marshal(amendments)
	out, err := ConvertHDFToOpenVEX(body, testVersion)
	require.NoError(t, err)
	doc := parseDoc(t, out)
	require.Len(t, doc.Statements, 1)
	s := doc.Statements[0]
	assert.Equal(t, "fixed", s.Status, "POA&M with all milestones completed promotes to 'fixed'")
	assert.Contains(t, s.ActionStatement, "Apply 1.2.4")
}

func TestConvertHDFToOpenVEX_NonCVEOverridesAreSkipped(t *testing.T) {
	t.Parallel()
	now, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	exp, _ := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "Mixed",
		Overrides: []hdf.StandaloneOverride{
			{Type: hdf.FalsePositive, RequirementID: "AC-2", Status: &passed, AppliedAt: now, ExpiresAt: exp, AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"}, Reason: "policy"},
			{Type: hdf.FalsePositive, RequirementID: "CVE-2024-99999", Status: &passed, AppliedAt: now, ExpiresAt: exp, AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"}, Reason: "not affected"},
		},
	}
	body, _ := json.Marshal(amendments)
	out, err := ConvertHDFToOpenVEX(body, testVersion)
	require.NoError(t, err)
	doc := parseDoc(t, out)
	require.Len(t, doc.Statements, 1)
	assert.Equal(t, "CVE-2024-99999", doc.Statements[0].Vulnerability.Name)
}

func TestConvertHDFToOpenVEX_ErrorsWhenNoCVEs(t *testing.T) {
	t.Parallel()
	now, _ := time.Parse(time.RFC3339, "2026-01-01T00:00:00Z")
	exp, _ := time.Parse(time.RFC3339, "2027-01-01T00:00:00Z")
	passed := hdf.Passed
	amendments := hdf.HDFAmendments{
		Name: "No CVE",
		Overrides: []hdf.StandaloneOverride{{
			Type: hdf.Attestation, RequirementID: "NIST-AC-1", Status: &passed,
			AppliedAt: now, ExpiresAt: exp,
			AppliedBy: hdf.Identity{Type: hdf.Simple, Identifier: "x"},
			Reason:    "policy",
		}},
	}
	body, _ := json.Marshal(amendments)
	_, err := ConvertHDFToOpenVEX(body, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no overrides with CVE-shaped requirementIds")
}

func TestConvertHDFToOpenVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToOpenVEX([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertHDFToOpenVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertHDFToOpenVEX(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestProductsFor_PrefersComponentRef(t *testing.T) {
	t.Parallel()
	ref := "pkg:npm/foo@1.2.3"
	got := productsFor(&hdf.StandaloneOverride{ComponentRef: &ref, Reason: "Products: IGNORED"})
	require.Len(t, got, 1)
	assert.Equal(t, ref, got[0].ID)
}

func TestProductsFor_ParsesProductsLine(t *testing.T) {
	t.Parallel()
	got := productsFor(&hdf.StandaloneOverride{Reason: "prose\nProducts: A, B, C"})
	require.Len(t, got, 3)
	assert.Equal(t, "C", got[2].ID)
}

func TestProductsFor_DefaultsWhenNothingPresent(t *testing.T) {
	t.Parallel()
	got := productsFor(&hdf.StandaloneOverride{Reason: "no products"})
	require.Len(t, got, 1)
	assert.Equal(t, defaultProductID, got[0].ID)
}

func TestBuildDocumentID_UsesAmendmentIDWhenPresent(t *testing.T) {
	t.Parallel()
	id := "ABC-123"
	a := &hdf.HDFAmendments{AmendmentID: &id}
	got := buildDocumentID([]byte("input"), a)
	assert.Equal(t, openvexNamespace+"vex-ABC-123", got)
}

func TestBuildDocumentID_HashesInputOtherwise(t *testing.T) {
	t.Parallel()
	a := &hdf.HDFAmendments{}
	got := buildDocumentID([]byte("input"), a)
	assert.Contains(t, got, openvexNamespace+"vex-")
}

// TestGoldenParity asserts byte-for-byte output against frozen golden files.
// The TypeScript test asserts against the SAME files, guaranteeing TS↔Go parity.
func TestGoldenParity(t *testing.T) {
	for _, name := range []string{"multi-status-amendments", "spring-boot-log4j-amendments"} {
		out, err := ConvertHDFToOpenVEX(loadInput(t, name+".json"), testVersion)
		require.NoError(t, err)
		goldenPath := filepath.Join("..", "fixtures", "expected", name+".openvex.json")
		if os.Getenv("UPDATE_GOLDEN") == "1" {
			require.NoError(t, os.WriteFile(goldenPath, out, 0o644))
			continue
		}
		golden, err := os.ReadFile(goldenPath)
		require.NoError(t, err, "read golden %s", goldenPath)
		assert.Equal(t, string(golden), string(out), "golden mismatch for %s", name)
	}
}
