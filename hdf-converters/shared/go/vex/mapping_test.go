package vex

import (
	"testing"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	"github.com/stretchr/testify/assert"
)

func TestNormalizeStatus(t *testing.T) {
	t.Parallel()
	cases := map[string]Status{
		"not_affected":           StatusNotAffected,
		"known_not_affected":     StatusNotAffected,
		"false_positive":         StatusNotAffected,
		"affected":               StatusAffected,
		"known_affected":         StatusAffected,
		"exploitable":            StatusAffected,
		"fixed":                  StatusFixed,
		"first_fixed":            StatusFixed,
		"resolved":               StatusFixed,
		"resolved_with_pedigree": StatusFixed,
		"under_investigation":    StatusUnderInvestigation,
		"in_triage":              StatusUnderInvestigation,
		"  NOT_AFFECTED  ":       StatusNotAffected,
	}
	for raw, want := range cases {
		got, ok := NormalizeStatus(raw)
		assert.Truef(t, ok, "expected %q to normalize", raw)
		assert.Equalf(t, want, got, "for %q", raw)
	}

	for _, unknown := range []string{"", "garbage", "recommended", "last_affected"} {
		_, ok := NormalizeStatus(unknown)
		assert.Falsef(t, ok, "expected %q to be unknown", unknown)
	}
}

func TestNormalizeJustification(t *testing.T) {
	t.Parallel()
	cases := map[string]hdf.Justification{
		"component_not_present":                             hdf.ComponentNotPresent,
		"code_not_present":                                  hdf.ComponentNotPresent,
		"vulnerable_code_not_present":                       hdf.VulnerableCodeNotPresent,
		"vulnerable_code_not_in_execute_path":               hdf.VulnerableCodeNotInExecutePath,
		"code_not_reachable":                                hdf.VulnerableCodeNotInExecutePath,
		"vulnerable_code_cannot_be_controlled_by_adversary": hdf.VulnerableCodeCannotBeControlledByAdversary,
		"inline_mitigations_already_exist":                  hdf.InlineMitigationsAlreadyExist,
		"protected_by_mitigating_control":                   hdf.InlineMitigationsAlreadyExist,
	}
	for raw, want := range cases {
		got, ok := NormalizeJustification(raw)
		assert.Truef(t, ok, "expected %q to normalize", raw)
		assert.Equalf(t, want, got, "for %q", raw)
	}

	for _, unknown := range []string{"", "requires_configuration", "protected_by_compiler", "garbage"} {
		_, ok := NormalizeJustification(unknown)
		assert.Falsef(t, ok, "expected %q to be unknown (importer must preserve raw value)", unknown)
	}
}

func TestImportTargetFor(t *testing.T) {
	t.Parallel()

	target, ok := ImportTargetFor(StatusNotAffected)
	assert.True(t, ok)
	assert.Equal(t, hdf.FalsePositive, target.OverrideType)
	assert.NotNil(t, target.Status)
	assert.Equal(t, hdf.Passed, *target.Status)
	assert.True(t, target.SetJustification)

	target, ok = ImportTargetFor(StatusFixed)
	assert.True(t, ok)
	assert.Equal(t, hdf.Poam, target.OverrideType)
	assert.Nil(t, target.Status, "fixed maps to a POA&M, not a status change — real system has not been re-scanned")
	assert.NotEmpty(t, target.POAMActionTemplate)

	_, ok = ImportTargetFor(StatusAffected)
	assert.False(t, ok, "affected is informational; consumer creates amendment later if they act")

	_, ok = ImportTargetFor(StatusUnderInvestigation)
	assert.False(t, ok, "under_investigation is informational")
}

func TestExportStatusFor(t *testing.T) {
	t.Parallel()

	_, ok := ExportStatusFor(nil, false, false)
	assert.False(t, ok, "no consumer action = no VEX statement")

	just := hdf.ComponentNotPresent
	got, ok := ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.FalsePositive, Justification: &just}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusNotAffected, got, "justification set always emits not_affected")

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.OverrideTypeWaiver}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusAffected, got, "waiver = consumer accepts risk on a real finding")

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.RiskAdjustment}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusAffected, got)

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.OperationalRequirement}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusAffected, got)

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.Poam}, true, true)
	assert.True(t, ok)
	assert.Equal(t, StatusFixed, got, "POAM closure requires BOTH all-milestones-complete AND chained-as-latest")

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.Poam}, true, false)
	assert.True(t, ok)
	assert.Equal(t, StatusAffected, got, "milestones done but no closure amendment chained = still in flight")

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.Poam}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusAffected, got)

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.FalsePositive}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusNotAffected, got)

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.Attestation}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusNotAffected, got)

	got, ok = ExportStatusFor(&hdf.StandaloneOverride{Type: hdf.Inherited}, false, false)
	assert.True(t, ok)
	assert.Equal(t, StatusNotAffected, got)
}

func TestSupplierEvidence(t *testing.T) {
	t.Parallel()

	ev := SupplierEvidence("https://example.com/openvex.json", "OpenVEX from Vendor X")
	assert.NotNil(t, ev)
	assert.Equal(t, hdf.URL, ev.Type)
	assert.Equal(t, "https://example.com/openvex.json", ev.Data)
	assert.NotNil(t, ev.Description)
	assert.Equal(t, "OpenVEX from Vendor X", *ev.Description)

	ev = SupplierEvidence("https://example.com/openvex.json", "")
	assert.NotNil(t, ev)
	assert.Equal(t, "Upstream VEX statement", *ev.Description, "fallback description when caller has none")

	assert.Nil(t, SupplierEvidence("", "anything"), "no URI = no evidence; don't fabricate")
	assert.Nil(t, SupplierEvidence("   ", "anything"))
}
