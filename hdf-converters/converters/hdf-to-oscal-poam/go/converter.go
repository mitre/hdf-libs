// Package hdftooscalpoam converts HDF Amendments to OSCAL Plan of Action and
// Milestones (POA&M) format. This is the reverse direction of the oscal-poam
// to HDF converter.
package hdftooscalpoam

import (
	"encoding/json"
	"fmt"
	"time"

	oscal "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"
	shared "github.com/mitre/hdf-converters/shared/go"
	hdf "github.com/mitre/hdf-schema"
)

// ConvertHDFToOSCALPOAM converts HDF Amendments JSON to OSCAL POA&M JSON.
// This is a RawConvertFn — it takes raw bytes and returns raw bytes.
func ConvertHDFToOSCALPOAM(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-oscal-poam", 0); err != nil {
		return nil, err
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("hdf-to-oscal-poam: empty input")
	}

	var amendments hdf.HDFAmendments
	if err := json.Unmarshal(input, &amendments); err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-poam: failed to parse JSON: %w", err)
	}

	poam, err := amendmentsToPOAM(&amendments, converterVersion)
	if err != nil {
		return nil, err
	}

	// Wrap in OscalDocument envelope
	doc := oscal.OscalDocument{
		PlanOfActionAndMilestones: poam,
	}

	output, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("hdf-to-oscal-poam: failed to serialize OSCAL output: %w", err)
	}

	return output, nil
}

// amendmentsToPOAM converts parsed HDFAmendments to an OSCAL PlanOfActionAndMilestones.
func amendmentsToPOAM(amendments *hdf.HDFAmendments, converterVersion string) (*oscal.PlanOfActionAndMilestones, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	// Build metadata
	meta := oscal.Metadata{
		Title:        amendments.Name,
		LastModified: now,
		Version:      "1.0.0",
		OscalVersion: oscal.OscalVersion,
	}

	// Add responsible parties from appliedBy
	if amendments.AppliedBy != nil {
		partyUUID := oscal.GenerateUUID()
		meta.Parties = []oscal.Party{
			{
				UUID: partyUUID,
				Type: "person",
				Name: amendments.AppliedBy.Identifier,
			},
		}
		meta.ResponsibleParties = []oscal.ResponsibleParty{
			{
				RoleID:   "prepared-by",
				PartyIDs: []string{partyUUID},
			},
		}
		meta.Roles = []oscal.Role{
			{
				ID:    "prepared-by",
				Title: "Prepared By",
			},
		}
	}

	// Build import-ssp
	var importSSP *oscal.ImportSSP
	if amendments.SystemRef != nil && *amendments.SystemRef != "" {
		importSSP = &oscal.ImportSSP{Href: *amendments.SystemRef}
	} else {
		importSSP = &oscal.ImportSSP{Href: "#"}
	}

	// Convert overrides to poam-items and collect risks
	var poamItems []oscal.POAMItem
	var risks []oscal.Risk

	for i := range amendments.Overrides {
		override := &amendments.Overrides[i]
		item, itemRisks := overrideToPOAMItem(override)
		poamItems = append(poamItems, item)
		risks = append(risks, itemRisks...)
	}

	poam := &oscal.PlanOfActionAndMilestones{
		UUID:      oscal.GenerateUUID(),
		Metadata:  meta,
		ImportSSP: importSSP,
		Risks:     risks,
		POAMItems: poamItems,
	}

	return poam, nil
}

// overrideToPOAMItem converts a single StandaloneOverride to a POAMItem
// and its associated Risk(s).
func overrideToPOAMItem(override *hdf.StandaloneOverride) (oscal.POAMItem, []oscal.Risk) {
	riskUUID := oscal.GenerateUUID()

	// Map HDF status to OSCAL risk status
	riskStatus := oscal.HDFStatusToOSCALRiskStatus(override.Status)

	// Convert requirement ID from NIST notation to OSCAL control ID
	controlID := oscal.NistTagToControlID(override.RequirementID)

	// Build risk props with impacted-control-id
	riskProps := []oscal.Property{
		{
			Name:  "impacted-control-id",
			Value: controlID,
		},
	}

	// Build remediations from milestones
	var remediations []oscal.Remediation
	for _, ms := range override.Milestones {
		rem := oscal.Remediation{
			UUID:        oscal.GenerateUUID(),
			Lifecycle:   "planned",
			Title:       ms.Description,
			Description: ms.Description,
		}
		remediations = append(remediations, rem)
	}

	// Build risk log entry for expiration tracking
	var riskLog *oscal.RiskLog
	if !override.ExpiresAt.IsZero() {
		riskLog = &oscal.RiskLog{
			Entries: []oscal.RiskLogEntry{
				{
					UUID:         oscal.GenerateUUID(),
					Title:        "Scheduled review",
					Description:  "Amendment expiration date",
					Start:        override.ExpiresAt.UTC().Format(time.RFC3339),
					StatusChange: riskStatus,
				},
			},
		}
	}

	risk := oscal.Risk{
		UUID:         riskUUID,
		Title:        override.RequirementID,
		Description:  override.Reason,
		Status:       riskStatus,
		Props:        riskProps,
		Remediations: remediations,
		RiskLog:      riskLog,
	}

	item := oscal.POAMItem{
		UUID:        oscal.GenerateUUID(),
		Title:       override.RequirementID,
		Description: override.Reason,
		RelatedRisks: []oscal.RelatedRef{
			{RiskUUID: riskUUID},
		},
	}

	return item, []oscal.Risk{risk}
}
