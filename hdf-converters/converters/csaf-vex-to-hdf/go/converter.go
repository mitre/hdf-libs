// Package csafvex converts CSAF VEX (csaf_vex profile) documents to HDF
// Amendments.
//
// CSAF (Common Security Advisory Framework) VEX is the OASIS-standardized
// vendor-advisory format. Each document carries a richer envelope than
// OpenVEX (publisher, tracking, product_tree) and per-vulnerability
// product_status buckets (known_not_affected, fixed, known_affected, etc.).
//
// The converter targets HDF Amendments (not Results) per the
// amendment-output pattern documented in build-converter.md Step 4f.
// 'fixed' becomes an open POA&M, not a status flip — supplier claim is
// not assessed-system evidence.
//
// Spec: https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
package csafvex

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

const defaultExpiryHorizon = 365 * 24 * time.Hour

// Document is the CSAF VEX top-level envelope.
type Document struct {
	Document        DocumentMeta    `json:"document"`
	ProductTree     *ProductTree    `json:"product_tree,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// DocumentMeta is the CSAF document envelope.
type DocumentMeta struct {
	Category    string      `json:"category"`
	CSAFVersion string      `json:"csaf_version"`
	Title       string      `json:"title,omitempty"`
	Publisher   Publisher   `json:"publisher"`
	Tracking    Tracking    `json:"tracking"`
	Notes       []Note      `json:"notes,omitempty"`
	References  []Reference `json:"references,omitempty"`
}

// Publisher identifies the document author.
type Publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Tracking holds version/release metadata.
type Tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	CurrentReleaseDate string     `json:"current_release_date"`
	InitialReleaseDate string     `json:"initial_release_date"`
	RevisionHistory    []Revision `json:"revision_history,omitempty"`
}

// Revision tracks one revision in the document history.
type Revision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

// Note carries free-text content.
type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

// Reference is an external URI.
type Reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url"`
}

// ProductTree describes the product taxonomy. We resolve product_ids
// through it on import to surface structured AffectedPackage entries
// instead of opaque CSAFPID-XYZ strings.
type ProductTree struct {
	Branches         []Branch          `json:"branches,omitempty"`
	FullProductNames []FullProductName `json:"full_product_names,omitempty"`
}

// Branch is one node in the (recursive) product_tree.branches array.
type Branch struct {
	Category string           `json:"category,omitempty"`
	Name     string           `json:"name,omitempty"`
	Product  *FullProductName `json:"product,omitempty"`
	Branches []Branch         `json:"branches,omitempty"`
}

// FullProductName carries a CSAF product leaf — a name plus an opaque
// product_id used inside the document.
type FullProductName struct {
	Name                        string                       `json:"name,omitempty"`
	ProductID                   string                       `json:"product_id,omitempty"`
	ProductIdentificationHelper *ProductIdentificationHelper `json:"product_identification_helper,omitempty"`
}

// ProductIdentificationHelper carries portable identifiers attached to a
// CSAF product. We extract purl (preferred) and cpe (fallback).
type ProductIdentificationHelper struct {
	Purl string `json:"purl,omitempty"`
	CPE  string `json:"cpe,omitempty"`
}

// Vulnerability is one CVE-scoped entry.
type Vulnerability struct {
	CVE           string         `json:"cve,omitempty"`
	IDs           []VulnID       `json:"ids,omitempty"`
	Notes         []Note         `json:"notes,omitempty"`
	ProductStatus *ProductStatus `json:"product_status,omitempty"`
	Threats       []Threat       `json:"threats,omitempty"`
	Remediations  []Remediation  `json:"remediations,omitempty"`
	Flags         []Flag         `json:"flags,omitempty"`
	References    []Reference    `json:"references,omitempty"`
}

// VulnID is an alternate identifier (vendor advisory id, GHSA, etc.).
type VulnID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

// ProductStatus is the per-vulnerability product bucket map. Only the
// buckets we map are typed; others are accepted for forward compatibility
// but unused.
type ProductStatus struct {
	FirstAffected      []string `json:"first_affected,omitempty"`
	FirstFixed         []string `json:"first_fixed,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	LastAffected       []string `json:"last_affected,omitempty"`
	Recommended        []string `json:"recommended,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

// Threat carries impact/exploitation details.
type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// Remediation carries fix instructions.
type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
	URL        string   `json:"url,omitempty"`
}

// Flag is a justification statement for not_affected products.
type Flag struct {
	Date       string   `json:"date,omitempty"`
	Label      string   `json:"label"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// ConvertCSAFVEXToHDF parses a CSAF VEX document and produces an HDF
// Amendments document.
func ConvertCSAFVEXToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	if err := shared.ValidateJSONSize(input, "csaf-vex-to-hdf", 0); err != nil {
		return nil, err
	}
	var doc Document
	if err := json.Unmarshal(input, &doc); err != nil {
		return nil, fmt.Errorf("parse CSAF VEX: %w", err)
	}
	if doc.Document.Category != "csaf_vex" {
		return nil, fmt.Errorf("csaf-vex-to-hdf: document.category is %q; only 'csaf_vex' is supported", doc.Document.Category)
	}

	docTime := hdfutil.ParseTimestamp(doc.Document.Tracking.CurrentReleaseDate)
	if docTime.IsZero() {
		docTime = time.Now().UTC()
	}

	productLookup := buildProductLookup(doc.ProductTree)

	overrides := make([]hdf.StandaloneOverride, 0)
	for i := range doc.Vulnerabilities {
		overrides = append(overrides, vulnerabilityToOverrides(&doc.Vulnerabilities[i], &doc, docTime, productLookup)...)
	}

	if len(overrides) == 0 {
		return nil, fmt.Errorf("csaf-vex-to-hdf: CSAF VEX document contains no actionable statements (only affected/under_investigation/recommended); no amendment to write")
	}

	name := "CSAF VEX statements"
	if doc.Document.Publisher.Name != "" {
		name = fmt.Sprintf("CSAF VEX statements from %s", doc.Document.Publisher.Name)
	}
	description := fmt.Sprintf("Imported VEX advisory %s", doc.Document.Tracking.ID)

	docVersion := doc.Document.Tracking.Version
	var versionPtr *string
	if docVersion != "" {
		versionPtr = &docVersion
	}

	return &hdf.HDFAmendments{
		Name:        name,
		Description: &description,
		Overrides:   overrides,
		AppliedBy:   identityFor(doc.Document.Publisher),
		Generator: &hdf.Generator{
			Name:    "csaf-vex-to-hdf",
			Version: converterVersion,
		},
		Integrity: shared.InputIntegrity(input),
		Version:   versionPtr,
	}, nil
}

// vulnerabilityToOverrides emits one override per actionable status bucket
// on the vulnerability. A vuln with both known_not_affected and fixed
// buckets produces TWO overrides (one falsePositive, one POA&M). Buckets
// with no canonical mapping are skipped.
func vulnerabilityToOverrides(vuln *Vulnerability, doc *Document, docTime time.Time, productLookup map[string]hdf.AffectedPackage) []hdf.StandaloneOverride {
	if vuln.CVE == "" {
		return nil
	}
	status := vuln.ProductStatus
	if status == nil {
		return nil
	}

	var out []hdf.StandaloneOverride
	if len(status.KnownNotAffected) > 0 {
		if o, ok := buildOverride(vuln, doc, docTime, vex.StatusNotAffected, status.KnownNotAffected, productLookup); ok {
			out = append(out, o)
		}
	}
	fixedProducts := append(append([]string{}, status.Fixed...), status.FirstFixed...)
	if len(fixedProducts) > 0 {
		if o, ok := buildOverride(vuln, doc, docTime, vex.StatusFixed, fixedProducts, productLookup); ok {
			out = append(out, o)
		}
	}
	// known_affected / first_affected / last_affected / under_investigation /
	// recommended produce no override (informational; consumer creates an
	// amendment later if they decide to act).
	return out
}

func buildOverride(vuln *Vulnerability, doc *Document, docTime time.Time, canonical vex.Status, products []string, productLookup map[string]hdf.AffectedPackage) (hdf.StandaloneOverride, bool) {
	target, ok := vex.ImportTargetFor(canonical)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}
	override := hdf.StandaloneOverride{
		Type:             target.OverrideType,
		Status:           target.Status,
		RequirementID:    vuln.CVE,
		AppliedAt:        docTime,
		ExpiresAt:        docTime.Add(defaultExpiryHorizon),
		AppliedBy:        *identityFor(doc.Document.Publisher),
		Reason:           buildReason(vuln, products),
		AffectedPackages: resolveAffectedPackages(products, productLookup),
	}

	if target.SetJustification {
		if j, jok := pickJustification(vuln, products); jok {
			override.Justification = &j
		}
	}

	if ev := vex.SupplierEvidence(advisoryURI(doc), "CSAF VEX advisory"); ev != nil {
		override.Evidence = append(override.Evidence, *ev)
	}
	for _, r := range vuln.References {
		desc := r.Summary
		if desc == "" {
			desc = r.Category
		}
		if ev := vex.SupplierEvidence(r.URL, desc); ev != nil {
			override.Evidence = append(override.Evidence, *ev)
		}
	}

	if target.OverrideType == hdf.Poam {
		desc := target.POAMActionTemplate
		if action := firstActionRemediation(vuln, products); action != "" {
			desc = action
		}
		override.Milestones = []hdf.Milestone{{
			Description:         desc,
			Status:              hdf.Pending,
			EstimatedCompletion: docTime.Add(defaultExpiryHorizon),
		}}
	}

	return override, true
}

// pickJustification returns the first flag whose product_ids overlap with
// the override's product scope, normalized through the shared VEX helper.
func pickJustification(vuln *Vulnerability, products []string) (hdf.Justification, bool) {
	scope := setFrom(products)
	for _, f := range vuln.Flags {
		if !overlap(f.ProductIDs, scope) {
			continue
		}
		if j, ok := vex.NormalizeJustification(f.Label); ok {
			return j, true
		}
	}
	return "", false
}

func firstActionRemediation(vuln *Vulnerability, products []string) string {
	scope := setFrom(products)
	for _, r := range vuln.Remediations {
		if len(r.ProductIDs) > 0 && !overlap(r.ProductIDs, scope) {
			continue
		}
		if r.Category == "vendor_fix" || r.Category == "mitigation" || r.Category == "workaround" {
			if r.Details != "" {
				return r.Details
			}
		}
	}
	return ""
}

// buildReason composes the override reason from CSAF prose (description
// note + product-scoped threat details). Justification and product list
// are fully structured fields now (Justification enum +
// Standalone_Override.affectedPackages); neither is mirrored into reason.
// Falls back to a status synopsis when CSAF carries no prose so the
// schema-required `reason` string is never empty.
func buildReason(vuln *Vulnerability, products []string) string {
	parts := make([]string, 0, 4)
	scope := setFrom(products)
	for _, n := range vuln.Notes {
		if n.Category == "description" && n.Text != "" {
			parts = append(parts, n.Text)
		}
	}
	for _, t := range vuln.Threats {
		if t.Details == "" {
			continue
		}
		if len(t.ProductIDs) > 0 && !overlap(t.ProductIDs, scope) {
			continue
		}
		parts = append(parts, t.Details)
	}
	if len(parts) == 0 {
		return fmt.Sprintf("Imported from CSAF VEX (%s)", vuln.CVE)
	}
	return strings.Join(parts, "\n")
}

func identityFor(p Publisher) *hdf.Identity {
	if p.Name == "" {
		return &hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: "csaf-vex-import"}
	}
	id := hdf.Identity{Type: hdf.Simple, Identifier: p.Name}
	if p.Category != "" {
		desc := p.Category
		id.Description = &desc
	}
	return &id
}

func advisoryURI(doc *Document) string {
	if doc.Document.Publisher.Namespace != "" && doc.Document.Tracking.ID != "" {
		return strings.TrimRight(doc.Document.Publisher.Namespace, "/") + "/" + doc.Document.Tracking.ID
	}
	return doc.Document.Tracking.ID
}

func setFrom(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, s := range items {
		out[s] = struct{}{}
	}
	return out
}

// overlap is only called with non-empty product scopes.
func overlap(ids []string, scope map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := scope[id]; ok {
			return true
		}
	}
	return false
}

// buildProductLookup walks a CSAF product_tree and returns a lookup from
// product_id to a structured AffectedPackage. Prefers
// product_identification_helper.purl, then .cpe. Entries without a portable
// identifier (purl/cpe) are dropped — the CSAF `name` field is human-readable
// and rarely decomposes cleanly to name+version+ecosystem.
func buildProductLookup(tree *ProductTree) map[string]hdf.AffectedPackage {
	lookup := make(map[string]hdf.AffectedPackage)
	if tree == nil {
		return lookup
	}
	for _, fp := range tree.FullProductNames {
		registerProduct(fp, lookup, branchContext{})
	}
	walkBranches(tree.Branches, lookup, branchContext{})
	return lookup
}

type branchContext struct {
	productName string
	version     string
}

func walkBranches(branches []Branch, lookup map[string]hdf.AffectedPackage, ctx branchContext) {
	for _, b := range branches {
		// Track product_name and product_version branches so leaf products
		// can recover name+version even when no
		// product_identification_helper is set.
		next := ctx
		switch b.Category {
		case "product_name":
			if b.Name != "" {
				next.productName = b.Name
			}
		case "product_version":
			if b.Name != "" {
				next.version = b.Name
			}
		}
		if b.Product != nil {
			registerProduct(*b.Product, lookup, next)
		}
		if len(b.Branches) > 0 {
			walkBranches(b.Branches, lookup, next)
		}
	}
}

func registerProduct(fp FullProductName, lookup map[string]hdf.AffectedPackage, ctx branchContext) {
	if fp.ProductID == "" {
		return
	}
	helper := fp.ProductIdentificationHelper
	if helper != nil && helper.Purl != "" {
		if pkg := vex.AffectedPackageFromIdentifier(helper.Purl); pkg != nil {
			lookup[fp.ProductID] = *pkg
			return
		}
	}
	if helper != nil && helper.CPE != "" {
		if pkg := vex.AffectedPackageFromIdentifier(helper.CPE); pkg != nil {
			lookup[fp.ProductID] = *pkg
			return
		}
	}
	// No portable identifier — fall back to ancestor product_name +
	// product_version branches when both are present. Ecosystem stays
	// generic; CSAF doesn't disambiguate package managers.
	if ctx.productName != "" && ctx.version != "" {
		name := ctx.productName
		version := ctx.version
		eco := hdf.Generic
		lookup[fp.ProductID] = hdf.AffectedPackage{
			Name:      &name,
			Version:   &version,
			Ecosystem: &eco,
		}
	}
}

func resolveAffectedPackages(productIDs []string, lookup map[string]hdf.AffectedPackage) []hdf.AffectedPackage {
	out := make([]hdf.AffectedPackage, 0, len(productIDs))
	seen := map[string]bool{}
	for _, id := range productIDs {
		pkg, ok := lookup[id]
		if !ok {
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
		out = append(out, pkg)
	}
	return out
}
