// Package vex provides shared mapping between VEX (OpenVEX, CSAF VEX,
// CycloneDX VEX) and HDF Amendments. Importers normalize ecosystem-specific
// statuses + justifications to the canonical forms here; exporters render
// HDF override state back to the canonical VEX shape.
//
// Synthesis happens only where the consumer has explicitly acted. The
// helper never invents amendments from raw findings, and never claims a
// real system is patched without a closure amendment chained on top of an
// open POA&M (real-system vs abstract-vuln distinction — see
// memory/amendment-output-converter-pattern.md).
package vex

import (
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Status is the canonical VEX status. The three ecosystems use slightly
// different vocabularies; importers and exporters translate to/from this.
type Status string

const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// NormalizeStatus maps an ecosystem-specific status string to the canonical
// Status. Returns ("", false) for values that do not have a clean mapping
// (caller should warn and skip, not guess).
func NormalizeStatus(raw string) (Status, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "not_affected", "known_not_affected", "false_positive":
		return StatusNotAffected, true
	case "affected", "known_affected", "exploitable":
		return StatusAffected, true
	case "fixed", "first_fixed", "resolved", "resolved_with_pedigree":
		return StatusFixed, true
	case "under_investigation", "in_triage":
		return StatusUnderInvestigation, true
	}
	return "", false
}

// NormalizeJustification maps an ecosystem-specific justification string to
// the canonical HDF Justification enum. Returns ("", false) for unknown
// values; callers SHOULD preserve the original string in evidence[] or
// reason instead of dropping it (the schema spec wants pass-through on
// unknown values, not rejection).
//
// CycloneDX adds vocabulary HDF does not yet model (requires_configuration,
// protected_by_compiler, etc.); those are deliberately returned as unknown
// so the converter has a chance to log + preserve the raw value.
func NormalizeJustification(raw string) (hdf.Justification, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "component_not_present", "code_not_present":
		return hdf.ComponentNotPresent, true
	case "vulnerable_code_not_present":
		return hdf.VulnerableCodeNotPresent, true
	case "vulnerable_code_not_in_execute_path", "code_not_reachable":
		return hdf.VulnerableCodeNotInExecutePath, true
	case "vulnerable_code_cannot_be_controlled_by_adversary":
		return hdf.VulnerableCodeCannotBeControlledByAdversary, true
	case "inline_mitigations_already_exist", "protected_by_mitigating_control":
		return hdf.InlineMitigationsAlreadyExist, true
	}
	return "", false
}

// ImportTarget describes the HDF amendment shape an importer should
// synthesize for a given canonical VEX statement. Returns (nil, false) for
// statuses that should NOT produce an amendment ("affected" and
// "under_investigation" are informational — the consumer creates an
// amendment later if they decide to act).
type ImportTarget struct {
	// OverrideType the importer should set on the synthesized override.
	OverrideType hdf.OverrideType
	// Status the importer should set when type permits it. Nil when the
	// override type carries its semantics in another field (POA&M).
	Status *hdf.ResultStatus
	// SetJustification is true when the canonical VEX status implies the
	// importer should populate the override's justification (not_affected).
	SetJustification bool
	// POAMActionTemplate is set for the "fixed" path: vendor reports a fix
	// but the real system has not been re-scanned, so we synthesize an open
	// POA&M with this action_statement reminding the consumer to apply and
	// verify. Caller is expected to fill in the version reference.
	POAMActionTemplate string
}

// ImportTargetFor returns the amendment shape an importer should produce
// for the given canonical VEX status. ok=false means "do not synthesize an
// amendment for this statement."
func ImportTargetFor(status Status) (ImportTarget, bool) {
	passed := hdf.Passed
	switch status {
	case StatusNotAffected:
		return ImportTarget{
			OverrideType:     hdf.FalsePositive,
			Status:           &passed,
			SetJustification: true,
		}, true
	case StatusFixed:
		failed := hdf.Failed
		return ImportTarget{
			OverrideType: hdf.Poam,
			// Status stays 'failed' on the open POA&M: VEX 'fixed' is an
			// abstract supplier claim about a product version, not evidence
			// the assessed system has the patch. Re-scan is required to
			// change the effective status.
			Status:             &failed,
			POAMActionTemplate: "vendor reports fix; apply and re-scan to verify",
		}, true
	case StatusAffected, StatusUnderInvestigation:
		return ImportTarget{}, false
	}
	return ImportTarget{}, false
}

// ExportStatusFor returns the canonical VEX status an exporter should emit
// for the given HDF override (or nil override = no consumer action). Returns
// ("", false) when no VEX statement should be emitted — the consumer has
// not acted, and VEX requires a deliberate statement.
//
// allMilestonesCompleted is consulted only for POA&M overrides. closureChained
// is true when this override is chained as the latest amendment in a chain
// whose milestones are all completed — that is the only signal that a POA&M
// has been actually closed (as opposed to "milestones happen to all be done
// on an in-flight POA&M, but no closure amendment was filed").
func ExportStatusFor(override *hdf.StandaloneOverride, allMilestonesCompleted, closureChained bool) (Status, bool) {
	if override == nil {
		return "", false
	}
	if override.Justification != nil {
		return StatusNotAffected, true
	}
	switch override.Type {
	case hdf.FalsePositive, hdf.Attestation, hdf.Inherited:
		return StatusNotAffected, true
	case hdf.OverrideTypeWaiver, hdf.RiskAdjustment, hdf.OperationalRequirement:
		return StatusAffected, true
	case hdf.Poam:
		if allMilestonesCompleted && closureChained {
			return StatusFixed, true
		}
		return StatusAffected, true
	}
	return "", false
}

// SupplierEvidence builds an HDF Evidence entry pointing at the upstream VEX
// document. Used by importers to preserve provenance (the original
// supplier's statement) even though we lose the structured statement_id.
//
// Returns nil when sourceURI is empty — we don't synthesize evidence we
// don't have.
func SupplierEvidence(sourceURI, description string) *hdf.Evidence {
	if strings.TrimSpace(sourceURI) == "" {
		return nil
	}
	desc := description
	if desc == "" {
		desc = "Upstream VEX statement"
	}
	return &hdf.Evidence{
		Type:        hdf.URL,
		Description: &desc,
		Data:        sourceURI,
	}
}
