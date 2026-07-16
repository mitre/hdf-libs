package oscal

import (
	"fmt"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// ConvertPOAMToHDF converts an OSCAL Plan of Action and Milestones (POA&M)
// document to HDF Amendments. Each poam-item becomes a StandaloneOverride
// with type "poam".
func ConvertPOAMToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	doc, err := ParseOscalDocument(input, "plan-of-action-and-milestones", "oscal-poam")
	if err != nil {
		return nil, err
	}

	return poamToHDFAmendments(doc.PlanOfActionAndMilestones, input, converterVersion)
}

// poamToHDFAmendments converts a parsed PlanOfActionAndMilestones to HDFAmendments.
// Every emitted date is extracted from the OSCAL source — the override deadline
// from risk.deadline, milestone ETAs from remediation task timing, appliedAt
// from metadata.last-modified. Conversion FAILS LOUD rather than fabricating a
// missing deadline: a POA&M with no time commitment defeats its purpose.
func poamToHDFAmendments(poam *PlanOfActionAndMilestones, rawInput []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	integrity := shared.InputIntegrity(rawInput)
	meta := ExtractMetadata(poam.Metadata)

	// Build risk lookup map for efficient access
	riskMap := buildRiskMap(poam.Risks)

	// Convert poam-items to StandaloneOverrides
	limitedPOAMItems := shared.LimitSliceWithWarning(poam.POAMItems, 0, "POA&M item")
	overrides := make([]hdf.StandaloneOverride, 0, len(limitedPOAMItems))
	for i := range limitedPOAMItems {
		override, err := poamItemToOverride(&limitedPOAMItems[i], riskMap, poam)
		if err != nil {
			return nil, err
		}
		overrides = append(overrides, override)
	}

	// Extract systemRef from import-ssp
	var systemRef *string
	if poam.ImportSSP != nil && poam.ImportSSP.Href != "" {
		systemRef = hdfutil.Ptr(poam.ImportSSP.Href)
	}

	// Build appliedBy from metadata responsible-parties
	appliedBy := extractAppliedBy(poam.Metadata)

	genName := "oscal-poam-to-hdf"
	amendments := &hdf.HDFAmendments{
		Name:      ToKebabCase(poam.Metadata.Title, "oscal-poam"),
		Overrides: overrides,
		Integrity: integrity,
		SystemRef: systemRef,
		Version:   hdfutil.Ptr(meta.Version),
		AppliedBy: appliedBy,
		Generator: &hdf.Generator{
			Name:    genName,
			Version: converterVersion,
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

// poamItemToOverride converts a single POAMItem to a StandaloneOverride. Every
// date is sourced from the OSCAL document; a missing appliedAt or deadline is a
// hard error (fail loud) rather than a fabricated wall-clock value.
func poamItemToOverride(item *POAMItem, riskMap map[string]*Risk, poam *PlanOfActionAndMilestones) (hdf.StandaloneOverride, error) {
	requirementID := extractRequirementIDFromPOAMItem(item, riskMap)

	appliedAt, err := poamItemAppliedAt(poam)
	if err != nil {
		return hdf.StandaloneOverride{}, fmt.Errorf("poam-item %q: %w", requirementID, err)
	}
	expiresAt, err := poamItemExpiresAt(item, riskMap)
	if err != nil {
		return hdf.StandaloneOverride{}, fmt.Errorf("poam-item %q: %w", requirementID, err)
	}

	status := poamItemStatus(item, riskMap)
	override := hdf.StandaloneOverride{
		Type:          hdf.Poam,
		RequirementID: requirementID,
		Reason:        poamItemReason(item),
		Status:        &status,
		AppliedBy:     poamItemAppliedBy(poam),
		AppliedAt:     appliedAt,
		ExpiresAt:     expiresAt,
		Milestones:    extractMilestones(item, riskMap),
	}

	return override, nil
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
		Type:       hdf.IdentityTypeSystem,
		Identifier: "oscal-poam-converter",
	}
}

// poamItemAppliedAt returns the appliedAt timestamp from the document's
// metadata.last-modified. OSCAL requires last-modified, so its absence is a
// malformed document — fail loud rather than stamp a wall-clock time.
func poamItemAppliedAt(poam *PlanOfActionAndMilestones) (time.Time, error) {
	if t := hdfutil.ParseTimestamp(poam.Metadata.LastModified); !t.IsZero() {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("no usable metadata.last-modified for appliedAt")
}

// poamItemExpiresAt returns the override deadline from the related risk's
// `deadline`. This is the enforceable time commitment of the POA&M; if no
// related risk carries a usable deadline the conversion fails loud rather than
// invent one (a POA&M without a deadline is meaningless).
func poamItemExpiresAt(item *POAMItem, riskMap map[string]*Risk) (time.Time, error) {
	for _, rr := range item.RelatedRisks {
		risk, ok := riskMap[rr.RiskUUID]
		if !ok {
			continue
		}
		if t := hdfutil.ParseTimestamp(risk.Deadline); !t.IsZero() {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("no related risk carries a usable deadline; a POA&M requires a time commitment")
}

// extractMilestones builds milestones from the planned remediation tasks of the
// item's related risks. Each task's within-date-range end is its estimated
// completion. Tasks without a usable end date are skipped (the milestones array
// is optional) — never fabricated — since Milestone.estimatedCompletion is
// required and must reflect real source data.
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
			for i := range rem.Tasks {
				task := &rem.Tasks[i]
				if task.Timing == nil || task.Timing.WithinDateRange == nil {
					continue
				}
				eta := hdfutil.ParseTimestamp(task.Timing.WithinDateRange.End)
				if eta.IsZero() {
					continue
				}
				milestones = append(milestones, hdf.Milestone{
					Description:         milestoneDescription(task),
					EstimatedCompletion: eta,
					Status:              hdf.Pending,
				})
			}
		}
	}

	return milestones
}

// milestoneDescription renders a milestone label from an OSCAL task: its title,
// with the description appended when present.
func milestoneDescription(task *Task) string {
	if task.Description != "" {
		return task.Title + ": " + task.Description
	}
	return task.Title
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
