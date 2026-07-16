package openvex

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

func TestConvertOpenVEXToHDF_SpringBootLog4j(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "spring-boot-log4j.openvex.json")
	result, err := ConvertOpenVEXToHDF(input, testVersion)
	require.NoError(t, err)

	assert.Contains(t, result.Name, "Spring Builds")
	require.Len(t, result.Overrides, 1)

	o := result.Overrides[0]
	assert.Equal(t, "CVE-2021-44228", o.RequirementID)
	assert.Equal(t, hdf.FalsePositive, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Passed, *o.Status)
	require.NotNil(t, o.Justification)
	assert.Equal(t, hdf.VulnerableCodeNotInExecutePath, *o.Justification)
	assert.Contains(t, o.Reason, "Spring Boot users")
	assert.NotContains(t, o.Reason, "Products:")
	require.NotEmpty(t, o.AffectedPackages)
	require.NotNil(t, o.AffectedPackages[0].Purl)
	assert.Equal(t,
		"pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
		*o.AffectedPackages[0].Purl)
	require.Len(t, o.Evidence, 1)
	assert.Equal(t, hdf.URL, o.Evidence[0].Type)

	body, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments output should validate: %s", v.Error())
}

func TestConvertOpenVEXToHDF_MultiStatus(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "multi-status.openvex.json")
	result, err := ConvertOpenVEXToHDF(input, testVersion)
	require.NoError(t, err)

	require.Len(t, result.Overrides, 2, "affected + under_investigation must NOT produce amendments")

	byCVE := map[string]hdf.StandaloneOverride{}
	for _, o := range result.Overrides {
		byCVE[o.RequirementID] = o
	}

	na, ok := byCVE["CVE-2024-1000"]
	require.True(t, ok)
	assert.Equal(t, hdf.FalsePositive, na.Type)
	require.NotNil(t, na.Justification)
	assert.Equal(t, hdf.ComponentNotPresent, *na.Justification)

	fixed, ok := byCVE["CVE-2024-2000"]
	require.True(t, ok)
	assert.Equal(t, hdf.Poam, fixed.Type, "fixed = open POA&M, not a passed flip")
	require.NotNil(t, fixed.Status)
	assert.Equal(t, hdf.Failed, *fixed.Status, "remains failed until consumer re-scans")
	require.Len(t, fixed.Milestones, 1)
	assert.Equal(t, hdf.Pending, fixed.Milestones[0].Status)
	assert.Contains(t, fixed.Reason, "Upgrade to 1.2.4 or later")

	_, hasAffected := byCVE["CVE-2024-3000"]
	assert.False(t, hasAffected, "affected = informational; consumer creates amendment if they act")
	_, hasInvestigation := byCVE["CVE-2024-4000"]
	assert.False(t, hasInvestigation, "under_investigation = informational")

	body, err := json.Marshal(result)
	require.NoError(t, err)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments output should validate: %s", v.Error())
}

func TestConvertOpenVEXToHDF_EmptyActionableStatementsRejected(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "empty.openvex.json")
	_, err := ConvertOpenVEXToHDF(input, testVersion)
	require.Error(t, err, "VEX with only affected/under_investigation statements must error — overrides.minItems=1")
	assert.Contains(t, err.Error(), "no actionable statements")
}

func TestConvertOpenVEXToHDF_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertOpenVEXToHDF(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "openvex-to-hdf")
}

func TestConvertOpenVEXToHDF_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertOpenVEXToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertOpenVEXToHDF_StatementWithoutVulnerabilityIsSkipped(t *testing.T) {
	t.Parallel()
	input := []byte(`{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id": "https://example.com/empty-vuln",
		"author": "test",
		"timestamp": "2026-01-01T00:00:00Z",
		"statements": [
			{"vulnerability": {}, "status": "not_affected"},
			{"vulnerability": {"name": "CVE-2024-9999"}, "status": "not_affected", "justification": "component_not_present"}
		]
	}`)
	result, err := ConvertOpenVEXToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1, "the unidentified statement is skipped; the well-formed one produces the override")
	assert.Equal(t, "CVE-2024-9999", result.Overrides[0].RequirementID)
}

func TestConvertOpenVEXToHDF_AuthorWithEmailGetsEmailIdentity(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "spring-boot-log4j.openvex.json")
	result, err := ConvertOpenVEXToHDF(input, testVersion)
	require.NoError(t, err)
	require.NotNil(t, result.AppliedBy)
	assert.Equal(t, hdf.Email, result.AppliedBy.Type)
}

// --- Ground-truth anchor (see shared/go/anchor.go) ---
// openvex emits one override per statement whose status is actionable — every
// status except 'affected' and 'under_investigation' (informational only).
// Count actionable statements from the source and assert the override count.
func countOpenVEXActionableStatements(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Statements []struct {
			Status string `json:"status"`
		} `json:"statements"`
	}
	require.NoError(t, json.Unmarshal(input, &doc))
	n := 0
	for _, s := range doc.Statements {
		if s.Status != "affected" && s.Status != "under_investigation" {
			n++
		}
	}
	return n
}

func TestConvertOpenVEXToHDF_OverrideAnchor(t *testing.T) {
	t.Parallel()
	input := loadInput(t, "multi-status.openvex.json")
	result, err := ConvertOpenVEXToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertOverrideCount(t, result, countOpenVEXActionableStatements(t, input),
		"multi-status.openvex.json: one override per actionable statement")
}

// TestSnapshots asserts every fixtures/expected/<input>.hdf.json golden reproduces
// whole-output, enforcing TS<->Go structural parity on the amendment document. The
// only volatile field is the doc-level timestamp (always masked); overrides carry
// no synthesized startTime.
func TestSnapshots(t *testing.T) {
	shared.RunSnapshotTests(t, "openvex-to-hdf", func(input []byte) (interface{}, error) {
		return ConvertOpenVEXToHDF(input, "1.0.0")
	})
}
