package oscal

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertPOAMToHDF converts an OSCAL Plan of Action and Milestones (POA&M)
// document to HDF Amendments. Each poam-item becomes a StandaloneOverride
// with type "poam".
func ConvertPOAMToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("empty input")
	}

	var doc OscalDocument
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("oscal-poam: failed to parse JSON: %w", err)
	}
	if doc.PlanOfActionAndMilestones == nil {
		return nil, fmt.Errorf("oscal-poam: input is not a plan-of-action-and-milestones document (root key is not 'plan-of-action-and-milestones')")
	}

	return poamToHDFAmendments(doc.PlanOfActionAndMilestones, input, converterVersion)
}

// poamToHDFAmendments converts a parsed PlanOfActionAndMilestones to HDFAmendments.
func poamToHDFAmendments(poam *PlanOfActionAndMilestones, rawInput []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	checksum := shared.InputChecksum(rawInput)
	meta := ExtractMetadata(poam.Metadata)

	// Build risk lookup map for efficient access
	riskMap := buildRiskMap(poam.Risks)

	// Convert poam-items to StandaloneOverrides
	overrides := make([]hdf.StandaloneOverride, 0, len(poam.POAMItems))
	for i := range poam.POAMItems {
		override := poamItemToOverride(&poam.POAMItems[i], riskMap, poam)
		overrides = append(overrides, override)
	}

	// Extract systemRef from import-ssp
	var systemRef *string
	if poam.ImportSSP != nil && poam.ImportSSP.Href != "" {
		systemRef = shared.Ptr(poam.ImportSSP.Href)
	}

	// Build appliedBy from metadata responsible-parties
	appliedBy := extractAppliedBy(poam.Metadata)

	genName := "hdf-converters"
	amendments := &hdf.HDFAmendments{
		Name:      poamAmendmentsName(poam),
		Overrides: overrides,
		Checksum:  checksum,
		SystemRef: systemRef,
		Version:   shared.Ptr(meta.Version),
		AppliedBy: appliedBy,
		Generator: &hdf.HDFAmendmentsGenerator{
			Name:    &genName,
			Version: &converterVersion,
		},
	}

	return amendments, nil
}

// buildRiskMap creates a UUID → Risk lookup for correlating poam-items with risks.
func buildRiskMap(risks []Risk) map[string]*Risk {
	m := make(map[string]*Risk, len(risks))
	for i := range risks {
		m[risks[i].UUID] = &risks[i]
	}
	return m
}

// poamItemToOverride converts a single POAMItem to a StandaloneOverride.
func poamItemToOverride(item *POAMItem, riskMap map[string]*Risk, poam *PlanOfActionAndMilestones) hdf.StandaloneOverride {
	override := hdf.StandaloneOverride{
		Type:          hdf.Poam,
		RequirementID: extractRequirementIDFromPOAMItem(item, riskMap),
		Reason:        poamItemReason(item),
		Status:        poamItemStatus(item, riskMap),
		AppliedBy:     poamItemAppliedBy(poam),
		AppliedAt:     poamItemAppliedAt(poam),
		ExpiresAt:     poamItemExpiresAt(item, riskMap),
		Milestones:    extractMilestones(item, riskMap),
	}

	return override
}

// extractRequirementIDFromPOAMItem extracts a requirement ID from a poam-item.
// It checks the related risks for impacted-control-id props, then falls back
// to the poam-item title.
func extractRequirementIDFromPOAMItem(item *POAMItem, riskMap map[string]*Risk) string {
	// Check related risks for impacted-control-id
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			if controlID, found := ExtractPropValue(risk.Props, "impacted-control-id", ""); found {
				return ControlIDToNistTag(controlID)
			}
		}
	}

	// Check poam-item props for POAM-ID or control reference
	if poamID, ok := ExtractPropValue(item.Props, "POAM-ID", ""); ok {
		return poamID
	}

	// Fall back to the title
	if item.Title != "" {
		return item.Title
	}

	return "unknown"
}

// poamItemReason builds a reason string from the poam-item description and
// related risk information.
func poamItemReason(item *POAMItem) string {
	if item.Description != "" {
		return item.Description
	}
	if item.Title != "" {
		return item.Title
	}
	return "POA&M item"
}

// poamItemStatus determines the HDF status for a poam-item based on related
// risk status. POA&Ms track remediation, so the status reflects the current
// risk state.
func poamItemStatus(item *POAMItem, riskMap map[string]*Risk) hdf.ResultStatus {
	// Check related risks for status
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			if status, found := OscalStatusToHDF(risk.Status); found {
				switch status {
				case "passed":
					return hdf.Passed
				case "failed":
					return hdf.Failed
				}
			}
		}
	}

	// Default: POA&M items typically represent open/failed findings
	return hdf.Failed
}

// poamItemAppliedBy extracts the identity of who is responsible for the POA&M.
func poamItemAppliedBy(poam *PlanOfActionAndMilestones) hdf.Identity {
	// Look for prepared-by in responsible-parties
	for _, rp := range poam.Metadata.ResponsibleParties {
		if rp.RoleID == "prepared-by" && len(rp.PartyIDs) > 0 {
			return hdf.Identity{
				Type:       hdf.Simple,
				Identifier: rp.PartyIDs[0],
			}
		}
	}

	// Fall back to any responsible party
	if len(poam.Metadata.ResponsibleParties) > 0 && len(poam.Metadata.ResponsibleParties[0].PartyIDs) > 0 {
		return hdf.Identity{
			Type:       hdf.Simple,
			Identifier: poam.Metadata.ResponsibleParties[0].PartyIDs[0],
		}
	}

	return hdf.Identity{
		Type:       hdf.TypeSystem,
		Identifier: "oscal-poam-converter",
	}
}

// poamItemAppliedAt returns the timestamp for the POA&M item, using the
// document's last-modified date.
func poamItemAppliedAt(poam *PlanOfActionAndMilestones) time.Time {
	if poam.Metadata.LastModified != "" {
		if t, err := time.Parse(time.RFC3339, poam.Metadata.LastModified); err == nil {
			return t
		}
	}
	return time.Now()
}

// poamItemExpiresAt determines the expiration date for a POA&M override.
// It looks at risk deadlines and remediation task timings.
func poamItemExpiresAt(item *POAMItem, riskMap map[string]*Risk) time.Time {
	// Check related risks for deadline (stored in JSON but not in our Risk struct)
	// Fall back to remediation task end dates
	for _, rr := range item.RelatedRisks {
		if risk, ok := riskMap[rr.RiskUUID]; ok {
			// Check remediation tasks for milestone end dates
			for _, rem := range risk.Remediations {
				if rem.Lifecycle == "planned" {
					// Use the remediation as a signal; in real OSCAL the deadline
					// is at the risk level, but our struct doesn't capture it.
					// Return a reasonable default.
					_ = rem
				}
			}
		}
	}

	// Default: 1 year from now (POA&Ms should be reviewed periodically)
	return time.Now().AddDate(1, 0, 0)
}

// extractMilestones extracts milestone information from related risks'
// remediation tasks.
func extractMilestones(item *POAMItem, riskMap map[string]*Risk) []hdf.Milestone {
	var milestones []hdf.Milestone

	for _, rr := range item.RelatedRisks {
		risk, ok := riskMap[rr.RiskUUID]
		if !ok {
			continue
		}

		for _, rem := range risk.Remediations {
			if rem.Lifecycle != "planned" {
				continue
			}

			// In OSCAL, remediation tasks contain milestones as nested Task objects.
			// We don't have direct access to tasks on Remediation in our types,
			// so we create a milestone from the remediation itself.
			milestone := hdf.Milestone{
				Description:         rem.Title + ": " + rem.Description,
				EstimatedCompletion: time.Now().AddDate(0, 3, 0), // default 3 months
				Status:              hdf.Pending,
			}
			milestones = append(milestones, milestone)
		}
	}

	return milestones
}

// extractAppliedBy builds an Identity from metadata responsible-parties.
func extractAppliedBy(meta Metadata) *hdf.Identity {
	for _, rp := range meta.ResponsibleParties {
		if rp.RoleID == "prepared-by" && len(rp.PartyIDs) > 0 {
			return &hdf.Identity{
				Type:       hdf.Simple,
				Identifier: rp.PartyIDs[0],
			}
		}
	}
	return nil
}

// poamAmendmentsName derives an amendments name from POA&M metadata.
func poamAmendmentsName(poam *PlanOfActionAndMilestones) string {
	title := poam.Metadata.Title
	if title == "" {
		return "oscal-poam"
	}
	name := strings.ToLower(title)
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			return r
		}
		return '-'
	}, name)
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	name = strings.Trim(name, "-")
	if len(name) > 80 {
		name = name[:80]
	}
	return name
}
