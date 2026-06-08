// Package openvex converts OpenVEX statements to HDF Amendments.
//
// VEX (Vulnerability Exploitability eXchange) is consumer-attached context
// for CVE findings. Even when the underlying claim originates upstream
// (a vendor / distributor), the act of attaching it in HDF is an amendment
// act — so this converter emits HDF Amendments rather than HDF Results.
//
// Real-system vs abstract-vuln: VEX 'fixed' is a supplier claim that a
// product version contains a fix. It does NOT mean the assessed system has
// that version installed. This converter therefore maps 'fixed' to an open
// POA&M (apply + verify), not to a status flip.
//
// Spec: https://github.com/openvex/spec (OPENVEX-SPEC.md)
package openvex

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/vex"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// defaultExpiryHorizon is the override expiresAt offset from the
// statement's timestamp. VEX statements are meant to be re-evaluated as
// new information arrives; one year is a defensive default consistent
// with the no-permanent-amendment rule on Standalone_Override.
const defaultExpiryHorizon = 365 * 24 * time.Hour

// Document is the OpenVEX top-level document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version,omitempty"`
	Statements []Statement `json:"statements"`
}

// Statement is one OpenVEX claim about a vulnerability + product pair.
type Statement struct {
	Vulnerability   Vulnerability `json:"vulnerability"`
	Products        []Product     `json:"products,omitempty"`
	Status          string        `json:"status"`
	Justification   string        `json:"justification,omitempty"`
	ImpactStatement string        `json:"impact_statement,omitempty"`
	ActionStatement string        `json:"action_statement,omitempty"`
	Timestamp       string        `json:"timestamp,omitempty"`
	Author          string        `json:"author,omitempty"`
}

// Vulnerability identifies a CVE / advisory.
type Vulnerability struct {
	ID          string   `json:"@id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Aliases     []string `json:"aliases,omitempty"`
}

// Product identifies the product the statement is about.
type Product struct {
	ID          string            `json:"@id,omitempty"`
	Identifiers map[string]string `json:"identifiers,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
}

// ConvertOpenVEXToHDF parses an OpenVEX document and produces an HDF
// Amendments document. Statements with status 'affected' or
// 'under_investigation' produce no amendment (informational only — the
// consumer creates an amendment later if they decide to act).
func ConvertOpenVEXToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	if err := shared.ValidateJSONSize(input, "openvex-to-hdf", 0); err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("parse OpenVEX: %w", err)
	}

	docTime := hdfutil.ParseTimestamp(doc.Timestamp)
	if docTime.IsZero() {
		docTime = time.Now().UTC()
	}

	overrides := make([]hdf.StandaloneOverride, 0, len(doc.Statements))
	for i := range doc.Statements {
		override, ok := statementToOverride(&doc.Statements[i], &doc, docTime)
		if !ok {
			continue
		}
		overrides = append(overrides, override)
	}

	// HDF Amendments requires overrides.minItems=1. A VEX document with only
	// 'affected' or 'under_investigation' statements has no consumer-action
	// payload, so we refuse to write an empty amendments document. The user
	// can ingest the same VEX document later once they decide to act.
	if len(overrides) == 0 {
		return nil, fmt.Errorf("openvex-to-hdf: VEX document contains no actionable statements (all 'affected' or 'under_investigation'); no amendment to write")
	}

	name := "OpenVEX statements"
	if doc.Author != "" {
		name = fmt.Sprintf("OpenVEX statements from %s", doc.Author)
	}
	description := "Imported VEX statements from " + truncateID(doc.ID)

	return &hdf.HDFAmendments{
		Name:        name,
		Description: &description,
		Overrides:   overrides,
		AppliedBy:   identityFor(doc.Author, doc.Role),
		Generator: &hdf.Generator{
			Name:    "openvex-to-hdf",
			Version: converterVersion,
		},
		Integrity: shared.InputIntegrity(input),
	}, nil
}

// statementToOverride converts one OpenVEX statement to an HDF override,
// or returns (_, false) when no amendment should be synthesized.
func statementToOverride(stmt *Statement, doc *Document, docTime time.Time) (hdf.StandaloneOverride, bool) {
	canonical, ok := vex.NormalizeStatus(stmt.Status)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}
	target, ok := vex.ImportTargetFor(canonical)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}

	requirementID := stmt.Vulnerability.Name
	if requirementID == "" {
		requirementID = stmt.Vulnerability.ID
	}
	if requirementID == "" {
		return hdf.StandaloneOverride{}, false
	}

	stmtTime := docTime
	if stmt.Timestamp != "" {
		if t := hdfutil.ParseTimestamp(stmt.Timestamp); !t.IsZero() {
			stmtTime = t
		}
	}

	author := stmt.Author
	if author == "" {
		author = doc.Author
	}

	productIDs := make([]string, 0, len(stmt.Products))
	for _, p := range stmt.Products {
		if p.ID != "" {
			productIDs = append(productIDs, p.ID)
		}
	}
	affectedPackages := vex.AffectedPackagesFromIdentifiers(productIDs)

	override := hdf.StandaloneOverride{
		Type:             target.OverrideType,
		Status:           target.Status,
		RequirementID:    requirementID,
		AppliedAt:        stmtTime,
		ExpiresAt:        stmtTime.Add(defaultExpiryHorizon),
		AppliedBy:        *identityFor(author, doc.Role),
		Reason:           buildReason(stmt, target.POAMActionTemplate),
		AffectedPackages: affectedPackages,
	}

	if target.SetJustification && stmt.Justification != "" {
		if j, jok := vex.NormalizeJustification(stmt.Justification); jok {
			override.Justification = &j
		}
	}

	if ev := vex.SupplierEvidence(doc.ID, "OpenVEX document"); ev != nil {
		override.Evidence = append(override.Evidence, *ev)
	}

	if target.OverrideType == hdf.Poam {
		override.Milestones = []hdf.Milestone{{
			Description:         target.POAMActionTemplate,
			Status:              hdf.Pending,
			EstimatedCompletion: stmtTime.Add(defaultExpiryHorizon),
		}}
	}

	return override, true
}

// buildReason composes the override reason from VEX free-text fields.
// Falls back to a status-derived stub when the upstream document has no
// human prose — never an empty string (reason is required).
// Justification and product list are fully structured fields now
// (Justification enum + Standalone_Override.affectedPackages); neither
// is mirrored into reason.
func buildReason(stmt *Statement, poamTemplate string) string {
	parts := make([]string, 0, 2)
	if stmt.ImpactStatement != "" {
		parts = append(parts, stmt.ImpactStatement)
	}
	if stmt.ActionStatement != "" {
		parts = append(parts, stmt.ActionStatement)
	}
	if len(parts) == 0 {
		if poamTemplate != "" {
			return poamTemplate
		}
		return fmt.Sprintf("Imported from OpenVEX status %q", stmt.Status)
	}
	return strings.Join(parts, "\n")
}

func identityFor(author, role string) *hdf.Identity {
	if author == "" {
		return &hdf.Identity{
			Type:       hdf.IdentityTypeSystem,
			Identifier: "openvex-import",
		}
	}
	idType := hdf.Simple
	if strings.Contains(author, "@") {
		idType = hdf.Email
	}
	id := hdf.Identity{
		Type:       idType,
		Identifier: author,
	}
	if role != "" {
		id.Description = &role
	}
	return &id
}

func truncateID(id string) string {
	const maxLen = 80
	if len(id) <= maxLen {
		return id
	}
	return id[:maxLen] + "..."
}
