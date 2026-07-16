// Package cyclonedxvex converts CycloneDX BOMs carrying VEX analysis
// statements to HDF Amendments.
//
// CycloneDX VEX is not a separate format — it is a CycloneDX BOM whose
// vulnerabilities[] carry an `analysis` object describing how the
// publisher analyzed the issue. The canonical statuses are
// {not_affected, exploitable, in_triage, resolved, resolved_with_pedigree,
// false_positive}. CycloneDX-specific justifications that have no HDF
// equivalent (requires_configuration, protected_by_compiler, etc.) are
// preserved verbatim in the reason field.
//
// Spec: https://cyclonedx.org/use-cases/#vulnerability-exploitability
package cyclonedxvex

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

// BOM is the CycloneDX top-level document.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber,omitempty"`
	Version         int             `json:"version,omitempty"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Components      []Component     `json:"components,omitempty"`
}

// Metadata carries publisher/tool/timestamp info.
type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Component *Component `json:"component,omitempty"`
	Authors   []Author   `json:"authors,omitempty"`
	Tools     []Tool     `json:"tools,omitempty"`
}

type Author struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// Component is referenced by affects[].ref via bom-ref.
type Component struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type,omitempty"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

// Vulnerability is one VEX statement.
type Vulnerability struct {
	ID          string        `json:"id"`
	Source      *Source       `json:"source,omitempty"`
	References  []Reference   `json:"references,omitempty"`
	Description string        `json:"description,omitempty"`
	Detail      string        `json:"detail,omitempty"`
	Analysis    *Analysis     `json:"analysis,omitempty"`
	Affects     []AffectedRef `json:"affects,omitempty"`
}

type Source struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

type Reference struct {
	ID     string  `json:"id"`
	Source *Source `json:"source,omitempty"`
}

// Analysis is the VEX-specific payload.
type Analysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// AffectedRef points at a component bom-ref.
type AffectedRef struct {
	Ref string `json:"ref"`
}

// ConvertCycloneDXVEXToHDF parses a CycloneDX BOM with VEX analysis
// statements and produces an HDF Amendments document.
func ConvertCycloneDXVEXToHDF(input []byte, converterVersion string) (*hdf.HDFAmendments, error) {
	if err := shared.ValidateJSONSize(input, "cyclonedx-vex-to-hdf", 0); err != nil {
		return nil, err
	}
	var bom BOM
	if err := json.Unmarshal(input, &bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX VEX: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return nil, fmt.Errorf("cyclonedx-vex-to-hdf: bomFormat is %q; only 'CycloneDX' is supported", bom.BOMFormat)
	}

	docTime := time.Now().UTC()
	if bom.Metadata != nil && bom.Metadata.Timestamp != "" {
		if t := hdfutil.ParseTimestamp(bom.Metadata.Timestamp); !t.IsZero() {
			docTime = t
		}
	}

	productLookup := buildProductLookup(&bom)

	overrides := make([]hdf.StandaloneOverride, 0)
	for i := range bom.Vulnerabilities {
		o, ok := vulnerabilityToOverride(&bom.Vulnerabilities[i], productLookup, docTime, &bom)
		if !ok {
			continue
		}
		overrides = append(overrides, o)
	}

	if len(overrides) == 0 {
		return nil, fmt.Errorf("cyclonedx-vex-to-hdf: BOM contains no actionable VEX statements (only exploitable/in_triage or no analysis); no amendment to write")
	}

	name := "CycloneDX VEX statements"
	publisher := publisherIdentityOrDefault(&bom)
	if publisher.Identifier != "" && publisher.Identifier != "cyclonedx-vex-import" {
		name = fmt.Sprintf("CycloneDX VEX statements from %s", publisher.Identifier)
	}
	description := "Imported CycloneDX VEX"
	if bom.SerialNumber != "" {
		description = fmt.Sprintf("Imported CycloneDX VEX %s", bom.SerialNumber)
	}

	return &hdf.HDFAmendments{
		Name:        name,
		Description: &description,
		Overrides:   overrides,
		AppliedBy:   publisher,
		Generator: &hdf.Generator{
			Name:    "cyclonedx-vex-to-hdf",
			Version: converterVersion,
		},
		Integrity: shared.InputIntegrity(input),
	}, nil
}

// vulnerabilityToOverride maps one CycloneDX vulnerability into an HDF
// override. Returns ok=false when the analysis state has no actionable
// canonical mapping (exploitable / in_triage).
func vulnerabilityToOverride(v *Vulnerability, productLookup map[string]Component, docTime time.Time, bom *BOM) (hdf.StandaloneOverride, bool) {
	if v.ID == "" || v.Analysis == nil {
		return hdf.StandaloneOverride{}, false
	}
	canonical, ok := vex.NormalizeStatus(v.Analysis.State)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}
	target, ok := vex.ImportTargetFor(canonical)
	if !ok {
		return hdf.StandaloneOverride{}, false
	}

	affectedPackages := affectedPackagesForVuln(v, productLookup)

	// componentRef is UUID-constrained on the HDF schema (it identifies an
	// HDF component by id, not a foreign-format identifier). Multi-product
	// VEX scoping lands in affectedPackages[] (structured) rather than in
	// the reason free-text field.
	override := hdf.StandaloneOverride{
		Type:             target.OverrideType,
		Status:           target.Status,
		RequirementID:    v.ID,
		AppliedAt:        docTime,
		ExpiresAt:        docTime.Add(defaultExpiryHorizon),
		AppliedBy:        *publisherIdentityOrDefault(bom),
		Reason:           buildReason(v),
		AffectedPackages: affectedPackages,
	}

	if target.SetJustification && v.Analysis.Justification != "" {
		if j, jok := vex.NormalizeJustification(v.Analysis.Justification); jok {
			override.Justification = &j
		}
	}

	if v.Source != nil && v.Source.URL != "" {
		if ev := vex.SupplierEvidence(v.Source.URL, sourceDescription(v.Source)); ev != nil {
			override.Evidence = append(override.Evidence, *ev)
		}
	}
	for _, r := range v.References {
		if r.Source == nil || r.Source.URL == "" {
			continue
		}
		if ev := vex.SupplierEvidence(r.Source.URL, sourceDescription(r.Source)); ev != nil {
			override.Evidence = append(override.Evidence, *ev)
		}
	}

	if target.OverrideType == hdf.Poam {
		desc := target.POAMActionTemplate
		if action := firstActionFromResponse(v.Analysis.Response); action != "" {
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

func buildReason(v *Vulnerability) string {
	parts := make([]string, 0, 2)
	if v.Description != "" {
		parts = append(parts, v.Description)
	}
	if v.Analysis != nil && v.Analysis.Detail != "" {
		parts = append(parts, v.Analysis.Detail)
	}
	// Justification and product list are fully structured fields now
	// (Justification enum + Standalone_Override.affectedPackages); neither
	// is mirrored into reason. Response[] hints are not echoed either —
	// POA&M overrides carry remediation context via milestones.
	return strings.Join(parts, "\n")
}

// affectedPackagesForVuln resolves CycloneDX affects[].ref entries into
// structured AffectedPackage entries. Looks up each bom-ref in the
// component table to recover purl, name and version. Opaque bom-refs
// without a component-table match are dropped — the schema forbids
// fabricating name+version, and bom-refs aren't portable outside the
// source BOM.
func affectedPackagesForVuln(v *Vulnerability, lookup map[string]Component) []hdf.AffectedPackage {
	out := make([]hdf.AffectedPackage, 0, len(v.Affects))
	seen := map[string]bool{}
	for _, a := range v.Affects {
		if a.Ref == "" {
			continue
		}
		var pkg *hdf.AffectedPackage
		if comp, ok := lookup[a.Ref]; ok {
			pkg = affectedPackageFromComponent(comp)
		} else {
			pkg = vex.AffectedPackageFromIdentifier(a.Ref)
		}
		if pkg == nil {
			continue
		}
		key := affectedPackageKey(*pkg)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, *pkg)
	}
	return out
}

func affectedPackageKey(pkg hdf.AffectedPackage) string {
	if pkg.Purl != nil {
		return "purl:" + *pkg.Purl
	}
	if pkg.Cpe != nil {
		return "cpe:" + *pkg.Cpe
	}
	name := ""
	ver := ""
	if pkg.Name != nil {
		name = *pkg.Name
	}
	if pkg.Version != nil {
		ver = *pkg.Version
	}
	return "nv:" + name + "@" + ver
}

// affectedPackageFromComponent builds an AffectedPackage from a CycloneDX
// component. Prefers structured purl decomposition; falls back to the
// component's name+version. Returns nil for components with neither a
// purl nor a name+version pair (schema forbids fabricating identity).
func affectedPackageFromComponent(c Component) *hdf.AffectedPackage {
	if c.Purl != "" {
		return vex.AffectedPackageFromIdentifier(c.Purl)
	}
	if c.Name != "" && c.Version != "" {
		name := c.Name
		version := c.Version
		eco := hdf.Generic
		return &hdf.AffectedPackage{
			Name:      &name,
			Version:   &version,
			Ecosystem: &eco,
		}
	}
	return nil
}

// buildProductLookup indexes components by bom-ref so affects[].ref can
// be resolved to richer identifiers (purl, name@version).
func buildProductLookup(bom *BOM) map[string]Component {
	lookup := map[string]Component{}
	if bom.Metadata != nil && bom.Metadata.Component != nil && bom.Metadata.Component.BOMRef != "" {
		lookup[bom.Metadata.Component.BOMRef] = *bom.Metadata.Component
	}
	for _, c := range bom.Components {
		if c.BOMRef != "" {
			lookup[c.BOMRef] = c
		}
	}
	return lookup
}

// firstActionFromResponse maps a CycloneDX response[] value to a short
// action statement. Only the most common semantics are translated;
// unknown values fall back to the empty string and the caller uses the
// shared default ("vendor reports fix; apply and re-scan to verify").
func firstActionFromResponse(resp []string) string {
	for _, r := range resp {
		switch strings.ToLower(strings.TrimSpace(r)) {
		case "update":
			return "Apply vendor update and re-scan to verify."
		case "rollback":
			return "Roll back to the unaffected version and re-scan to verify."
		case "workaround_available":
			return "Apply the documented workaround."
		}
	}
	return ""
}

func publisherIdentityOrDefault(bom *BOM) *hdf.Identity {
	if id := publisherIdentity(bom); id != nil {
		return id
	}
	return &hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: "cyclonedx-vex-import"}
}

func publisherIdentity(bom *BOM) *hdf.Identity {
	if bom.Metadata == nil {
		return nil
	}
	for _, a := range bom.Metadata.Authors {
		identifier := a.Email
		idType := hdf.Email
		if identifier == "" {
			identifier = a.Name
			idType = hdf.Simple
		}
		if identifier != "" {
			return &hdf.Identity{Type: idType, Identifier: identifier}
		}
	}
	for _, t := range bom.Metadata.Tools {
		name := strings.TrimSpace(strings.TrimSpace(t.Vendor) + " " + strings.TrimSpace(t.Name))
		if name != "" {
			return &hdf.Identity{Type: hdf.IdentityTypeSystem, Identifier: name}
		}
	}
	return nil
}

func sourceDescription(s *Source) string {
	if s == nil {
		return ""
	}
	if s.Name != "" {
		return s.Name
	}
	return ""
}
