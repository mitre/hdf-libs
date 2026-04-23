package oscal

import (
	"strings"

	shared "github.com/mitre/hdf-libs/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// ConvertSSPToHDF converts an OSCAL System Security Plan document to an
// HDFSystem. System characteristics map to top-level system fields, components
// map to HDF Components, and control implementations are used to populate
// baseline references on components.
func ConvertSSPToHDF(input []byte, converterVersion string) (*hdf.HDFSystem, error) {
	doc, err := ParseOscalDocument(input, "system-security-plan", "oscal-ssp")
	if err != nil {
		return nil, err
	}

	ssp := doc.SystemSecurityPlan
	integrity := shared.InputIntegrity(input)

	system := &hdf.HDFSystem{
		Name:      sspSystemName(ssp),
		Integrity: integrity,
		Generator: &hdf.Generator{
			Name:    "hdf-converters",
			Version: converterVersion,
		},
	}

	// Map system characteristics
	if sc := ssp.SystemCharacteristics; sc != nil {
		if sc.Description != "" {
			desc := sc.Description
			if sc.AuthorizationBound != nil && sc.AuthorizationBound.Description != "" {
				desc += "\n\nAuthorization Boundary: " + sc.AuthorizationBound.Description
			}
			system.Description = &desc
		}

		// Map categorization level from security impact level
		if sil := sc.SecurityImpactLevel; sil != nil {
			level := sspCategorizationLevel(sil)
			system.CategorizationLevel = level
		} else if sc.SecuritySensLevel != nil && *sc.SecuritySensLevel != "" {
			level := mapSensitivityToCategorizationLevel(*sc.SecuritySensLevel)
			system.CategorizationLevel = level
		}

		// Map authorization status from system status
		if sc.Status != nil {
			status := sspAuthorizationStatus(sc.Status.State)
			system.AuthorizationStatus = status
		}

		// Map boundary description
		if sc.AuthorizationBound != nil && sc.AuthorizationBound.Description != "" {
			system.BoundaryDescription = &sc.AuthorizationBound.Description
		}

		// Map system identifier
		if len(sc.SystemIDs) > 0 {
			system.Identifier = &sc.SystemIDs[0].ID
			if sc.SystemIDs[0].IdentifierType != "" {
				system.IdentifierScheme = &sc.SystemIDs[0].IdentifierType
			}
		}
	}

	// Map version from metadata
	meta := ExtractMetadata(ssp.Metadata)
	if meta.Version != "" {
		system.Version = &meta.Version
	}

	// Build component-UUID → control-ID mapping from control-implementation
	componentControls := buildComponentControlMap(ssp.ControlImplementation)

	// Map system-implementation components to HDF Components
	if si := ssp.SystemImplementation; si != nil {
		for _, sc := range si.Components {
			comp := sspComponentToHDFComponent(&sc, componentControls)
			system.Components = append(system.Components, comp)
		}
	}

	return system, nil
}

// sspSystemName extracts the system name from SSP metadata.
func sspSystemName(ssp *SystemSecurityPlan) string {
	if sc := ssp.SystemCharacteristics; sc != nil && sc.SystemName != "" {
		return sc.SystemName
	}
	if ssp.Metadata.Title != "" {
		return ssp.Metadata.Title
	}
	return "oscal-ssp"
}

// sspCategorizationLevel determines the FIPS 199 categorization level from the
// security impact level. Uses the high water mark across CIA objectives.
func sspCategorizationLevel(sil *SecurityImpactLevel) *hdf.CategorizationLevel {
	levels := []string{sil.Confidentiality, sil.Integrity, sil.Availability}

	highest := ""
	for _, l := range levels {
		normalized := normalizeFIPSLevel(l)
		if fipsLevelRank(normalized) > fipsLevelRank(highest) {
			highest = normalized
		}
	}

	if highest == "" {
		return nil
	}

	var level hdf.CategorizationLevel
	switch highest {
	case "high":
		level = hdf.CategorizationLevelHigh
	case "moderate":
		level = hdf.Moderate
	case "low":
		level = hdf.CategorizationLevelLow
	default:
		return nil
	}
	return &level
}

// normalizeFIPSLevel normalizes FIPS 199 impact level strings.
// Handles both "fips-199-moderate" and "moderate" formats.
func normalizeFIPSLevel(level string) string {
	lower := strings.ToLower(level)
	lower = strings.TrimPrefix(lower, "fips-199-")
	switch lower {
	case "high":
		return "high"
	case "moderate", "medium":
		return "moderate"
	case "low":
		return "low"
	default:
		return ""
	}
}

// fipsLevelRank returns a numeric rank for FIPS level comparison.
func fipsLevelRank(level string) int {
	switch level {
	case "high":
		return 3
	case "moderate":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// mapSensitivityToCategorizationLevel maps a security-sensitivity-level string
// to an HDF CategorizationLevel.
func mapSensitivityToCategorizationLevel(level string) *hdf.CategorizationLevel {
	normalized := normalizeFIPSLevel(level)
	if normalized == "" {
		return nil
	}
	var cat hdf.CategorizationLevel
	switch normalized {
	case "high":
		cat = hdf.CategorizationLevelHigh
	case "moderate":
		cat = hdf.Moderate
	case "low":
		cat = hdf.CategorizationLevelLow
	default:
		return nil
	}
	return &cat
}

// sspAuthorizationStatus maps an OSCAL system status state to an HDF
// AuthorizationStatus.
func sspAuthorizationStatus(state string) *hdf.AuthorizationStatus {
	var status hdf.AuthorizationStatus
	switch strings.ToLower(state) {
	case "operational":
		status = hdf.Authorized
	case "under-development":
		status = hdf.PendingAuthorization
	case "disposition":
		status = hdf.Revoked
	case "other":
		status = hdf.NotYetRequested
	default:
		return nil
	}
	return &status
}

// buildComponentControlMap builds a map of component UUID → set of control IDs
// from the SSP control-implementation section.
func buildComponentControlMap(ci *SSPControlImpl) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	if ci == nil {
		return result
	}

	for _, ir := range ci.ImplementedRequirements {
		controlID := ir.ControlID

		// Direct by-components on the implemented-requirement
		for _, bc := range ir.ByComponents {
			addComponentControl(result, bc.ComponentUUID, controlID)
		}

		// by-components within statements
		for _, stmt := range ir.Statements {
			for _, bc := range stmt.ByComponents {
				addComponentControl(result, bc.ComponentUUID, controlID)
			}
		}
	}

	return result
}

// addComponentControl adds a control ID to a component's control set.
func addComponentControl(m map[string]map[string]bool, compUUID, controlID string) {
	if _, ok := m[compUUID]; !ok {
		m[compUUID] = make(map[string]bool)
	}
	m[compUUID][controlID] = true
}

// sspComponentToHDFComponent converts an OSCAL SystemComponent to an HDF
// Component, using the component-control map to populate baseline references.
func sspComponentToHDFComponent(sc *SystemComponent, componentControls map[string]map[string]bool) hdf.Component {
	comp := hdf.Component{
		Name: sc.Title,
		Type: mapOSCALComponentType(sc.Type),
	}

	if sc.Description != "" {
		comp.Description = &sc.Description
	}

	// Add control IDs as baseline refs (NIST notation)
	if controls, ok := componentControls[sc.UUID]; ok {
		var refs []string
		for controlID := range controls {
			refs = append(refs, ControlIDToNistTag(controlID))
		}
		if len(refs) > 0 {
			comp.BaselineRefs = refs
		}
	}

	return comp
}

// mapOSCALComponentType maps an OSCAL component type string to an HDF
// Copyright (component type discriminator).
func mapOSCALComponentType(oscalType string) hdf.Copyright {
	switch strings.ToLower(oscalType) {
	case "software", "this-system":
		return hdf.Application
	case "service":
		return hdf.Application
	case "hardware":
		return hdf.Host
	case "network":
		return hdf.Network
	case "database":
		return hdf.Database
	case "storage":
		return hdf.Artifact
	default:
		return hdf.Application
	}
}
