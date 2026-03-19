// Package hdftooscalpoam converts HDF Amendments to OSCAL Plan of Action and
// Milestones (POA&M) format. This is the reverse direction of the oscal-poam
// to HDF converter.
package hdftooscalpoam

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	oscal "github.com/mitre/hdf-converters/converters/oscal-to-hdf/go"
	hdf "github.com/mitre/hdf-schema"
)

// oscalVersion is the OSCAL specification version emitted by this converter.
const oscalVersion = "1.1.2"

// nistEnhancementRe matches NIST 800-53 notation like "AC-2 (3)".
var nistEnhancementRe = regexp.MustCompile(`^([A-Z]{2}-\d+)\s*\((\d+)\)$`)

// ConvertHDFToOSCALPOAM converts HDF Amendments JSON to OSCAL POA&M JSON.
// This is a RawConvertFn — it takes raw bytes and returns raw bytes.
func ConvertHDFToOSCALPOAM(input []byte, converterVersion string) ([]byte, error) {
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
		OscalVersion: oscalVersion,
	}

	// Add responsible parties from appliedBy
	if amendments.AppliedBy != nil {
		partyUUID := generateUUID()
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
		UUID:      generateUUID(),
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
	riskUUID := generateUUID()

	// Map HDF status to OSCAL risk status
	riskStatus := hdfStatusToOSCAL(override.Status)

	// Convert requirement ID from NIST notation to OSCAL control ID
	controlID := nistTagToControlID(override.RequirementID)

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
			UUID:        generateUUID(),
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
					UUID:         generateUUID(),
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
		UUID:        generateUUID(),
		Title:       override.RequirementID,
		Description: override.Reason,
		RelatedRisks: []oscal.RelatedRef{
			{RiskUUID: riskUUID},
		},
	}

	return item, []oscal.Risk{risk}
}

// hdfStatusToOSCAL maps an HDF ResultStatus to an OSCAL risk status string.
// This is the reverse of OscalStatusToHDF in shared.go.
func hdfStatusToOSCAL(status hdf.ResultStatus) string {
	switch status {
	case hdf.Passed:
		return "closed"
	case hdf.Failed:
		return "open"
	case hdf.Error:
		return "open"
	case hdf.NotApplicable:
		return "closed"
	case hdf.NotReviewed:
		return "open"
	default:
		return "open"
	}
}

// nistTagToControlID converts a NIST 800-53 tag back to an OSCAL control ID.
// This is the reverse of ControlIDToNistTag in shared.go.
// Examples:
//
//	"AC-1"    -> "ac-1"
//	"AC-2 (3)" -> "ac-2.3"
//	"SI-7 (1)" -> "si-7.1"
func nistTagToControlID(tag string) string {
	tag = strings.TrimSpace(tag)
	if m := nistEnhancementRe.FindStringSubmatch(tag); m != nil {
		return fmt.Sprintf("%s.%s", strings.ToLower(m[1]), m[2])
	}
	return strings.ToLower(tag)
}

// generateUUID creates a version-4 UUID using crypto/rand.
func generateUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])
	// Set version 4
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant 10
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
