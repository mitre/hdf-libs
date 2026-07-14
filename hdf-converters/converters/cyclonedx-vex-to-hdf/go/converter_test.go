package cyclonedxvex

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

func TestConvertCycloneDXVEX_NotAffected(t *testing.T) {
	t.Parallel()
	result, err := ConvertCycloneDXVEXToHDF(loadInput(t, "case1-vex-not_affected.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)
	o := result.Overrides[0]
	assert.Equal(t, "CVE-2021-44228", o.RequirementID)
	assert.Equal(t, hdf.FalsePositive, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Passed, *o.Status)
	require.NotNil(t, o.Justification)
	assert.Equal(t, hdf.ComponentNotPresent, *o.Justification, "code_not_present normalizes to component_not_present")
	assert.Contains(t, o.Reason, "Class with vulnerable code was removed")
	assert.NotContains(t, o.Reason, "Products:")
	require.Len(t, o.AffectedPackages, 1, "product bom-ref resolves via metadata.component lookup")
	require.NotNil(t, o.AffectedPackages[0].Name)
	require.NotNil(t, o.AffectedPackages[0].Version)
	assert.Equal(t, "ABC", *o.AffectedPackages[0].Name)
	assert.Equal(t, "4.2", *o.AffectedPackages[0].Version)

	body, _ := json.Marshal(result)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid, "amendments output must validate: %s", v.Error())
}

func TestConvertCycloneDXVEX_Resolved(t *testing.T) {
	t.Parallel()
	result, err := ConvertCycloneDXVEXToHDF(loadInput(t, "case1-vex-fixed.json"), testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)
	o := result.Overrides[0]
	assert.Equal(t, hdf.Poam, o.Type)
	require.NotNil(t, o.Status)
	assert.Equal(t, hdf.Failed, *o.Status, "supplier 'resolved' becomes open POA&M pinned to failed")
	require.Len(t, o.Milestones, 1)
	assert.Equal(t, hdf.Pending, o.Milestones[0].Status)

	body, _ := json.Marshal(result)
	v := validators.ValidateAmendments(body)
	require.True(t, v.Valid)
}

func TestConvertCycloneDXVEX_AffectedAndUnderInvestigationProduceError(t *testing.T) {
	t.Parallel()
	_, err := ConvertCycloneDXVEXToHDF(loadInput(t, "case1-vex-affected.json"), testVersion)
	require.Error(t, err, "exploitable / affected = informational; no amendment")
	assert.Contains(t, err.Error(), "no actionable VEX statements")

	_, err = ConvertCycloneDXVEXToHDF(loadInput(t, "case1-vex-under_investigation.json"), testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no actionable VEX statements")
}

func TestConvertCycloneDXVEX_CycloneDXSpecificJustificationLandsInStructuredField(t *testing.T) {
	t.Parallel()
	// requires_configuration / protected_by_compiler etc. are part of the
	// HDF Justification enum (v3.2.x extension) and populate the structured
	// field directly — no reason-line passthrough needed.
	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"name": "X", "version": "1", "bom-ref": "px"}},
		"vulnerabilities": [{
			"id": "CVE-2026-1234",
			"analysis": {
				"state": "not_affected",
				"justification": "requires_configuration",
				"detail": "Needs explicit opt-in"
			},
			"affects": [{"ref": "px"}]
		}]
	}`)
	result, err := ConvertCycloneDXVEXToHDF(input, testVersion)
	require.NoError(t, err)
	require.Len(t, result.Overrides, 1)
	require.NotNil(t, result.Overrides[0].Justification)
	assert.Equal(t, hdf.RequiresConfiguration, *result.Overrides[0].Justification)
	assert.NotContains(t, result.Overrides[0].Reason, "VEX justification:",
		"justification should NOT be mirrored into reason — structured field is authoritative")
}

func TestConvertCycloneDXVEX_RejectsNonCycloneDX(t *testing.T) {
	t.Parallel()
	input := []byte(`{"bomFormat": "SPDX", "specVersion": "2.3"}`)
	_, err := ConvertCycloneDXVEXToHDF(input, testVersion)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CycloneDX")
}

func TestConvertCycloneDXVEX_RejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	_, err := ConvertCycloneDXVEXToHDF([]byte("not json"), testVersion)
	require.Error(t, err)
}

func TestConvertCycloneDXVEX_RejectsOversizedInput(t *testing.T) {
	t.Parallel()
	_, err := ConvertCycloneDXVEXToHDF(make([]byte, 51*1024*1024), testVersion)
	require.Error(t, err)
}

func TestFirstActionFromResponse(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "Apply vendor update and re-scan to verify.", firstActionFromResponse([]string{"update"}))
	assert.Equal(t, "Roll back to the unaffected version and re-scan to verify.", firstActionFromResponse([]string{"rollback"}))
	assert.Equal(t, "Apply the documented workaround.", firstActionFromResponse([]string{"workaround_available"}))
	assert.Equal(t, "", firstActionFromResponse([]string{"will_not_fix"}), "unmapped responses fall to empty so the caller uses the default action template")
	assert.Equal(t, "", firstActionFromResponse(nil))
}

func TestAffectedPackageFromComponent_PrefersPurl(t *testing.T) {
	t.Parallel()
	pkg := affectedPackageFromComponent(Component{Purl: "pkg:npm/x@1.0", Name: "x", Version: "1.0"})
	require.NotNil(t, pkg)
	require.NotNil(t, pkg.Purl)
	assert.Equal(t, "pkg:npm/x@1.0", *pkg.Purl)
	require.NotNil(t, pkg.Name)
	assert.Equal(t, "x", *pkg.Name)
	require.NotNil(t, pkg.Ecosystem)
	assert.Equal(t, hdf.Npm, *pkg.Ecosystem)
}

func TestAffectedPackageFromComponent_FallsBackToNameVersionGeneric(t *testing.T) {
	t.Parallel()
	pkg := affectedPackageFromComponent(Component{Name: "x", Version: "1.0"})
	require.NotNil(t, pkg)
	assert.Nil(t, pkg.Purl)
	require.NotNil(t, pkg.Name)
	assert.Equal(t, "x", *pkg.Name)
	require.NotNil(t, pkg.Version)
	assert.Equal(t, "1.0", *pkg.Version)
	require.NotNil(t, pkg.Ecosystem)
	assert.Equal(t, hdf.Generic, *pkg.Ecosystem)
}

func TestAffectedPackageFromComponent_DropsNameOnlyAndEmptyComponents(t *testing.T) {
	t.Parallel()
	assert.Nil(t, affectedPackageFromComponent(Component{Name: "x"}),
		"schema requires name+version+ecosystem OR purl OR cpe — name alone fails")
	assert.Nil(t, affectedPackageFromComponent(Component{BOMRef: "bom-ref-1"}),
		"a bom-ref alone isn't a portable identifier — drop")
	assert.Nil(t, affectedPackageFromComponent(Component{}))
}

// --- Ground-truth anchor (see shared/go/anchor.go) ---
// cyclonedx-vex emits one override per vulnerability with an actionable analysis
// state — every state except exploitable/in_triage (and analysis must be
// present). Count actionable statements independently of the converter. The
// committed fixtures are single-vulnerability status variants (want=1); a
// multi-vulnerability fixture would strengthen this (bead hdf-libs-2t2k).
func countCdxVexActionableVulns(t *testing.T, input []byte) int {
	t.Helper()
	var doc struct {
		Vulnerabilities []struct {
			Analysis *struct {
				State string `json:"state"`
			} `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(input, &doc))
	n := 0
	for _, v := range doc.Vulnerabilities {
		if v.Analysis == nil {
			continue
		}
		if v.Analysis.State != "exploitable" && v.Analysis.State != "in_triage" {
			n++
		}
	}
	return n
}

func TestConvertCycloneDXVEX_OverrideAnchor(t *testing.T) {
	input := loadInput(t, "case1-vex-fixed.json")
	result, err := ConvertCycloneDXVEXToHDF(input, testVersion)
	require.NoError(t, err)
	shared.AssertOverrideCount(t, result, countCdxVexActionableVulns(t, input),
		"case1-vex-fixed.json: one override per actionable VEX statement")
}
