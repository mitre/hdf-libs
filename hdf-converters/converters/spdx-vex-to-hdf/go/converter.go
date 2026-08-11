// Package spdxvex converts SPDX 3.0.1 JSON-LD security-profile documents
// (as produced by bootlin/sbom-cve-check) to HDF Amendments.
//
// SPDX-3 is JSON-LD: a top-level { "@context", "@graph" } where "@graph" is a
// flat array of typed, cross-referenced elements. The security profile adds
// VEX assessment relationships (security_Vex*VulnAssessmentRelationship) that
// link a security_Vulnerability (the CVE) to one or more software_Package
// elements. Each such relationship is one consumer-attached VEX statement, so
// like the sibling cyclonedx-vex / openvex converters this emits HDF Amendments
// rather than HDF Results.
//
// Real-system vs abstract-vuln: VEX 'fixed' is a supplier claim that a product
// version contains a fix. It does NOT mean the assessed system has that version
// installed. This converter therefore maps 'fixed' to an open POA&M (apply +
// verify), never a status flip to passed. 'affected' and 'under_investigation'
// are informational — vex.ImportTargetFor returns ok=false for them, so they
// produce no override (the consumer creates one later if they decide to act).
//
// Spec: https://spdx.github.io/spdx-spec/v3.0.1/ (security profile)
package spdxvex

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/vex"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// defaultExpiryHorizon is the override expiresAt offset from the statement's
// assessment time. VEX statements are meant to be re-evaluated as new
// information arrives; one year is a defensive default consistent with the
// no-permanent-amendment rule on Standalone_Override.
const defaultExpiryHorizon = 365 * 24 * time.Hour

// defaultAppliedByIdentifier is the fallback system identity when no supplier
// agent can be resolved for a statement.
const defaultAppliedByIdentifier = "spdx-vex-import"

// vexStatusByType maps the four SPDX-3 VEX assessment relationship subtypes to
// the canonical VEX status the shared mapping understands.
var vexStatusByType = map[string]vex.Status{
	"security_VexNotAffectedVulnAssessmentRelationship":        vex.StatusNotAffected,
	"security_VexFixedVulnAssessmentRelationship":              vex.StatusFixed,
	"security_VexAffectedVulnAssessmentRelationship":           vex.StatusAffected,
	"security_VexUnderInvestigationVulnAssessmentRelationship": vex.StatusUnderInvestigation,
}

// document is the SPDX-3 JSON-LD envelope.
type document struct {
	Context string         `json:"@context"`
	Graph   []graphElement `json:"@graph"`
}

// graphElement is a single element in the @graph. SPDX-3 elements are
// heterogeneous; this one struct carries every field this converter reads and
// relies on JSON's omit-absent-fields behavior to leave the rest zero-valued.
type graphElement struct {
	Type            string               `json:"type"`
	SpdxID          string               `json:"spdxId"`
	ID              string               `json:"@id"`
	Name            string               `json:"name"`
	Description     string               `json:"description"`
	CreationInfoRef string               `json:"creationInfo"`
	Created         string               `json:"created"`
	CreatedBy       []string             `json:"createdBy"`
	ExternalIDs     []externalIdentifier `json:"externalIdentifier"`
	ExternalRefs    []externalRef        `json:"externalRef"`

	// VEX / CVSS assessment relationship fields.
	RelationshipType  string   `json:"relationshipType"`
	From              string   `json:"from"`
	To                []string `json:"to"`
	Score             string   `json:"security_score"`
	Severity          string   `json:"security_severity"`
	VectorString      string   `json:"security_vectorString"`
	JustificationType string   `json:"security_justificationType"`
	ImpactStatement   string   `json:"security_impactStatement"`
	StatusNotes       string   `json:"security_statusNotes"`
	ActionStatement   string   `json:"security_actionStatement"`
}

type externalIdentifier struct {
	ExternalIdentifierType string   `json:"externalIdentifierType"`
	Identifier             string   `json:"identifier"`
	IdentifierLocator      []string `json:"identifierLocator"`
}

type externalRef struct {
	Locator []string `json:"locator"`
}

// graphIndex holds the cross-reference tables built from a single @graph.
type graphIndex struct {
	vulnByID     map[string]*graphElement // security_Vulnerability, keyed by spdxId
	pkgByID      map[string]*graphElement // software_Package, keyed by spdxId
	agentByID    map[string]string        // SoftwareAgent spdxId -> name
	creationByID map[string]*graphElement // CreationInfo, keyed by @id
	cvssByVuln   map[string]*graphElement // Cvss assessment, keyed by `from` vuln spdxId
}

// ConvertSPDXVEXToHDF parses an SPDX-3 security-profile document and produces an
// HDF Amendments document. Returns an error when the document carries no
// actionable VEX statements (only affected / under_investigation).
func ConvertSPDXVEXToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	if err := shared.ValidateJSONSize(input, "spdx-vex-to-hdf", 0); err != nil {
		return nil, err
	}
	var doc document
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("parse SPDX-3: %w", err)
	}
	if len(doc.Graph) == 0 {
		return nil, fmt.Errorf("spdx-vex-to-hdf: document has no @graph elements")
	}

	idx := buildIndex(&doc)

	overrides := make([]hdf.StandaloneOverride, 0)
	for i := range doc.Graph {
		el := &doc.Graph[i]
		if _, isVex := vexStatusByType[el.Type]; !isVex {
			continue
		}
		if o, ok := idx.relationshipToOverride(el); ok {
			overrides = append(overrides, o)
		}
	}

	if len(overrides) == 0 {
		return nil, fmt.Errorf("spdx-vex-to-hdf: SPDX document contains no actionable VEX statements (only affected/under_investigation); no amendment to write")
	}

	appliedBy := idx.documentIdentity(&doc)
	name := "SPDX VEX statements"
	if appliedBy.Identifier != "" && appliedBy.Identifier != defaultAppliedByIdentifier {
		name = fmt.Sprintf("SPDX VEX statements from %s", appliedBy.Identifier)
	}
	description := "Imported SPDX 3.0.1 security-profile VEX statements"

	return &hdf.HDFAmendments{
		Name:        name,
		Description: &description,
		Overrides:   overrides,
		AppliedBy:   &appliedBy,
		Generator: &hdf.Generator{
			Name:    "spdx-vex-to-hdf",
			Version: converterVersion,
		},
		Integrity: shared.InputIntegrity(input),
	}, nil
}

// buildIndex constructs the cross-reference tables for one document.
func buildIndex(doc *document) *graphIndex {
	idx := &graphIndex{
		vulnByID:     map[string]*graphElement{},
		pkgByID:      map[string]*graphElement{},
		agentByID:    map[string]string{},
		creationByID: map[string]*graphElement{},
		cvssByVuln:   map[string]*graphElement{},
	}
	for i := range doc.Graph {
		el := &doc.Graph[i]
		switch {
		case el.Type == "security_Vulnerability":
			idx.vulnByID[el.SpdxID] = el
		case el.Type == "software_Package":
			idx.pkgByID[el.SpdxID] = el
		case el.Type == "SoftwareAgent":
			if el.SpdxID != "" && el.Name != "" {
				idx.agentByID[el.SpdxID] = el.Name
			}
		case el.Type == "CreationInfo":
			if el.ID != "" {
				idx.creationByID[el.ID] = el
			}
		case isCvssType(el.Type):
			// First CVSS relationship per vulnerability wins (graph order).
			if _, seen := idx.cvssByVuln[el.From]; !seen && el.From != "" {
				idx.cvssByVuln[el.From] = el
			}
		}
	}
	return idx
}

// relationshipToOverride maps one VEX assessment relationship to an HDF
// override, or returns (_, false) when the status is informational
// (affected / under_investigation) or the CVE cannot be resolved.
func (idx *graphIndex) relationshipToOverride(rel *graphElement) (hdf.StandaloneOverride, bool) {
	canonical, ok := vexStatusByType[rel.Type]
	if !ok {
		return hdf.StandaloneOverride{}, false
	}
	target, ok := vex.ImportTargetFor(canonical)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}

	vuln := idx.vulnByID[rel.From]
	requirementID := cveIdentifier(vuln)
	if requirementID == "" {
		return hdf.StandaloneOverride{}, false
	}

	appliedAt := idx.createdAt(rel.CreationInfoRef)
	if appliedAt.IsZero() && vuln != nil {
		appliedAt = idx.createdAt(vuln.CreationInfoRef)
	}
	if appliedAt.IsZero() {
		appliedAt = time.Now().UTC()
	}

	override := hdf.StandaloneOverride{
		Type:             target.OverrideType,
		Status:           target.Status,
		RequirementID:    requirementID,
		AppliedAt:        appliedAt,
		ExpiresAt:        appliedAt.Add(defaultExpiryHorizon),
		AppliedBy:        idx.identityFor(rel.CreationInfoRef),
		Reason:           buildReason(vuln, rel, target.POAMActionTemplate),
		AffectedPackages: idx.affectedPackages(rel.To),
	}

	if target.SetJustification && rel.JustificationType != "" {
		if j, jok := vex.NormalizeJustification(rel.JustificationType); jok {
			override.Justification = &j
		}
	}

	if cvssRel := idx.cvssByVuln[rel.From]; cvssRel != nil {
		override.Cvss = buildCvss(cvssRel, requirementID)
	}

	if ev := supplierEvidenceFor(vuln); len(ev) > 0 {
		override.Evidence = ev
	}

	if target.OverrideType == hdf.Poam {
		desc := target.POAMActionTemplate
		if rel.ActionStatement != "" {
			desc = rel.ActionStatement
		}
		override.Milestones = []hdf.Milestone{{
			Description:         desc,
			Status:              hdf.Pending,
			EstimatedCompletion: appliedAt.Add(defaultExpiryHorizon),
		}}
	}

	return override, true
}

// affectedPackages resolves each product spdxId in `to` to its cpe23/purl
// identifier string and builds structured AffectedPackage entries.
func (idx *graphIndex) affectedPackages(productIDs []string) []hdf.AffectedPackage {
	identifiers := make([]string, 0, len(productIDs))
	for _, id := range productIDs {
		pkg := idx.pkgByID[id]
		if pkg == nil {
			continue
		}
		if ident := packageIdentifier(pkg); ident != "" {
			identifiers = append(identifiers, ident)
		}
	}
	return vex.AffectedPackagesFromIdentifiers(identifiers)
}

// createdAt resolves a creationInfo blank-node ref to its parsed created time.
func (idx *graphIndex) createdAt(creationInfoRef string) time.Time {
	if ci := idx.creationByID[creationInfoRef]; ci != nil && ci.Created != "" {
		if t := hdfutil.ParseTimestamp(ci.Created); !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}

// identityFor resolves the supplier identity behind a creationInfo ref: its
// first createdBy agent name, falling back to the system import default.
func (idx *graphIndex) identityFor(creationInfoRef string) hdf.Identity {
	if ci := idx.creationByID[creationInfoRef]; ci != nil {
		for _, agentID := range ci.CreatedBy {
			if name := idx.agentByID[agentID]; name != "" {
				return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: name}
			}
		}
	}
	return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: defaultAppliedByIdentifier}
}

// documentIdentity picks a document-level appliedBy: the SpdxDocument's
// creation agent when present, else the first agent in the graph, else the
// default system identity.
func (idx *graphIndex) documentIdentity(doc *document) hdf.Identity {
	for i := range doc.Graph {
		if doc.Graph[i].Type == "SpdxDocument" {
			if id := idx.identityFor(doc.Graph[i].CreationInfoRef); id.Identifier != defaultAppliedByIdentifier {
				return id
			}
		}
	}
	for i := range doc.Graph {
		if name := idx.agentByID[doc.Graph[i].SpdxID]; name != "" {
			return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: name}
		}
	}
	return hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: defaultAppliedByIdentifier}
}

// buildReason composes the override reason from the vulnerability description
// and the VEX statement's impact / status prose. Falls back to the POA&M
// action template or a status stub so reason is never empty (schema requires it).
func buildReason(vuln, rel *graphElement, poamTemplate string) string {
	parts := make([]string, 0, 3)
	if vuln != nil && vuln.Description != "" {
		parts = append(parts, vuln.Description)
	}
	if rel.ImpactStatement != "" {
		parts = append(parts, rel.ImpactStatement)
	}
	if rel.StatusNotes != "" {
		parts = append(parts, rel.StatusNotes)
	}
	if len(parts) == 0 {
		if poamTemplate != "" {
			return poamTemplate
		}
		return fmt.Sprintf("Imported from SPDX VEX relationship %q", rel.RelationshipType)
	}
	return strings.Join(parts, "\n")
}

// buildCvss constructs an HDF Cvss from an SPDX CVSS assessment relationship.
// Only fields the SPDX element carries are populated; Version is required and
// derived from the vector prefix or the relationship subtype.
func buildCvss(rel *graphElement, cve string) *hdf.Cvss {
	c := &hdf.Cvss{Version: cvssVersion(rel.Type, rel.VectorString)}
	if rel.Score != "" {
		if f, err := strconv.ParseFloat(rel.Score, 64); err == nil {
			c.BaseScore = &f
		}
	}
	if rel.VectorString != "" {
		v := rel.VectorString
		c.BaseVector = &v
	}
	if sev := cvssSeverity(rel.Severity); sev != "" {
		c.BaseSeverity = &sev
	}
	if cve != "" {
		src := cve
		c.Source = &src
	}
	return c
}

// cvssVersion derives the CVSS spec version from the vector prefix
// ("CVSS:3.1/...") when present, else from the relationship subtype.
func cvssVersion(relType, vector string) hdf.Version {
	if strings.HasPrefix(vector, "CVSS:") {
		rest := vector[len("CVSS:"):]
		if i := strings.IndexByte(rest, '/'); i > 0 {
			switch rest[:i] {
			case "2.0":
				return hdf.The20
			case "3.0":
				return hdf.The30
			case "3.1":
				return hdf.The31
			case "4.0":
				return hdf.The40
			}
		}
	}
	switch {
	case strings.Contains(relType, "CvssV2"):
		return hdf.The20
	case strings.Contains(relType, "CvssV4"):
		return hdf.The40
	default:
		return hdf.The31
	}
}

// cvssSeverity maps an SPDX security_severity label to the HDF CVSSSeverity
// enum. Returns "" for unknown labels (caller omits the field).
func cvssSeverity(raw string) hdf.CVSSSeverity {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return hdf.CVSSSeverityCritical
	case "high":
		return hdf.CVSSSeverityHigh
	case "medium":
		return hdf.CVSSSeverityMedium
	case "low":
		return hdf.CVSSSeverityLow
	case "none":
		return hdf.None
	}
	return ""
}

// supplierEvidenceFor collects deduplicated URL evidence from a vulnerability's
// externalRef locators and cve externalIdentifier locators.
func supplierEvidenceFor(vuln *graphElement) []hdf.Evidence {
	if vuln == nil {
		return nil
	}
	out := make([]hdf.Evidence, 0)
	seen := map[string]bool{}
	add := func(url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		if ev := vex.SupplierEvidence(url, "SPDX vulnerability reference"); ev != nil {
			out = append(out, *ev)
		}
	}
	for _, ref := range vuln.ExternalRefs {
		for _, loc := range ref.Locator {
			add(loc)
		}
	}
	for _, ext := range vuln.ExternalIDs {
		for _, loc := range ext.IdentifierLocator {
			add(loc)
		}
	}
	return out
}

// cveIdentifier returns the CVE id from a vulnerability's externalIdentifier
// entries (type "cve"), else "".
func cveIdentifier(vuln *graphElement) string {
	if vuln == nil {
		return ""
	}
	for _, ext := range vuln.ExternalIDs {
		if strings.EqualFold(ext.ExternalIdentifierType, "cve") && ext.Identifier != "" {
			return ext.Identifier
		}
	}
	return ""
}

// packageIdentifier returns a cpe23 or purl identifier string for a package,
// preferring purl. Returns "" when the package carries neither.
func packageIdentifier(pkg *graphElement) string {
	cpe := ""
	for _, ext := range pkg.ExternalIDs {
		switch strings.ToLower(ext.ExternalIdentifierType) {
		case "purl":
			if ext.Identifier != "" {
				return ext.Identifier
			}
		case "cpe23", "cpe22":
			if cpe == "" {
				cpe = ext.Identifier
			}
		}
	}
	return cpe
}

// isCvssType reports whether an element type is a CVSS assessment relationship.
func isCvssType(t string) bool {
	return strings.HasPrefix(t, "security_Cvss") && strings.HasSuffix(t, "VulnAssessmentRelationship")
}
