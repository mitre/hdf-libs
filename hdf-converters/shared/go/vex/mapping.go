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
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
// values; callers SHOULD log unknown values rather than silently dropping
// (the schema spec wants pass-through on unknown values, not rejection,
// but practically we expect the enum to be extended when a new vocabulary
// is integrated rather than carrying raw labels indefinitely).
//
// The HDF Justification enum (v3.2.x) covers:
//   - the original OpenVEX / CSAF VEX five values
//   - CycloneDX-specific reachability values (requires_*, protected_*)
//     that describe why a vulnerable code path is unreachable in the
//     deployed configuration.
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
	case "requires_configuration":
		return hdf.RequiresConfiguration, true
	case "requires_dependency":
		return hdf.RequiresDependency, true
	case "requires_environment":
		return hdf.RequiresEnvironment, true
	case "protected_by_compiler":
		return hdf.ProtectedByCompiler, true
	case "protected_at_runtime":
		return hdf.ProtectedAtRuntime, true
	case "protected_at_perimeter":
		return hdf.ProtectedAtPerimeter, true
	}
	return "", false
}

// JustificationForCycloneDX renders an HDF Justification value as the
// CycloneDX-native vocabulary. CycloneDX uses short-form names
// (code_not_present, code_not_reachable, protected_by_mitigating_control)
// for the three justifications shared with OpenVEX/CSAF, and shares the
// six CycloneDX-specific reachability values verbatim.
//
// Returns ("", false) when the HDF value has no equivalent in CycloneDX's
// enum (vulnerable_code_not_present and
// vulnerable_code_cannot_be_controlled_by_adversary do not appear in the
// CycloneDX 1.4 vocabulary). Callers should omit the justification field
// in that case rather than emit an invalid CycloneDX value.
func JustificationForCycloneDX(j hdf.Justification) (string, bool) {
	switch j {
	case hdf.ComponentNotPresent:
		return "code_not_present", true
	case hdf.VulnerableCodeNotInExecutePath:
		return "code_not_reachable", true
	case hdf.InlineMitigationsAlreadyExist:
		return "protected_by_mitigating_control", true
	case hdf.RequiresConfiguration, hdf.RequiresDependency, hdf.RequiresEnvironment,
		hdf.ProtectedByCompiler, hdf.ProtectedAtRuntime, hdf.ProtectedAtPerimeter:
		return string(j), true
	}
	// vulnerable_code_not_present and
	// vulnerable_code_cannot_be_controlled_by_adversary have no CycloneDX
	// equivalent; caller should omit the field.
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

// ecosystemFromPurlType maps a PURL `type` segment to the AffectedPackage
// ecosystem enum. Unknown types fall back to Generic, which the schema enum
// permits as a catch-all.
var ecosystemFromPurlType = map[string]hdf.Ecosystem{
	"npm":    hdf.Npm,
	"pypi":   hdf.Pypi,
	"rpm":    hdf.RPM,
	"deb":    hdf.Deb,
	"maven":  hdf.Maven,
	"gem":    hdf.Gem,
	"nuget":  hdf.Nuget,
	"golang": hdf.Go,
	"go":     hdf.Go,
	"cargo":  hdf.Cargo,
}

// AffectedPackageFromIdentifier builds an AffectedPackage from a single
// product identifier string emitted by a VEX format. Recognizes PURLs and
// CPE 2.3 strings; returns nil for opaque identifiers (importer should drop
// the entry — schema additions forbid fabricating name+version).
func AffectedPackageFromIdentifier(identifier string) *hdf.AffectedPackage {
	if identifier == "" {
		return nil
	}
	if strings.HasPrefix(identifier, "pkg:") {
		parsed := hdfutil.ParsePurl(identifier)
		if parsed != nil {
			pkg := &hdf.AffectedPackage{}
			purl := identifier
			pkg.Purl = &purl
			if parsed.Name != "" {
				name := parsed.Name
				pkg.Name = &name
			}
			if parsed.Version != nil && *parsed.Version != "" {
				v := *parsed.Version
				pkg.Version = &v
			}
			eco, ok := ecosystemFromPurlType[parsed.Type]
			if !ok {
				eco = hdf.Generic
			}
			pkg.Ecosystem = &eco
			return pkg
		}
		// Malformed purl with the prefix — preserve as purl-only.
		purl := identifier
		return &hdf.AffectedPackage{Purl: &purl}
	}
	if strings.HasPrefix(identifier, "cpe:2.3:") {
		cpe := identifier
		return &hdf.AffectedPackage{Cpe: &cpe}
	}
	return nil
}

// AffectedPackagesFromIdentifiers builds a deduplicated list of
// AffectedPackage entries from a sequence of identifier strings. Empty or
// unresolvable entries are dropped.
func AffectedPackagesFromIdentifiers(identifiers []string) []hdf.AffectedPackage {
	out := make([]hdf.AffectedPackage, 0, len(identifiers))
	seen := make(map[string]bool, len(identifiers))
	for _, id := range identifiers {
		pkg := AffectedPackageFromIdentifier(id)
		if pkg == nil {
			continue
		}
		var key string
		switch {
		case pkg.Purl != nil:
			key = "purl:" + *pkg.Purl
		case pkg.Cpe != nil:
			key = "cpe:" + *pkg.Cpe
		default:
			name := ""
			ver := ""
			if pkg.Name != nil {
				name = *pkg.Name
			}
			if pkg.Version != nil {
				ver = *pkg.Version
			}
			key = "nv:" + name + "@" + ver
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *pkg)
	}
	return out
}

// AffectedPackageToIdentifier renders an AffectedPackage as a single
// identifier string suitable for round-tripping into a VEX format. Prefers
// purl > cpe > name@version. Returns ("", false) when nothing identifying
// is set.
func AffectedPackageToIdentifier(pkg hdf.AffectedPackage) (string, bool) {
	if pkg.Purl != nil && *pkg.Purl != "" {
		return *pkg.Purl, true
	}
	if pkg.Cpe != nil && *pkg.Cpe != "" {
		return *pkg.Cpe, true
	}
	if pkg.Name != nil && *pkg.Name != "" {
		if pkg.Version != nil && *pkg.Version != "" {
			return *pkg.Name + "@" + *pkg.Version, true
		}
		return *pkg.Name, true
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
