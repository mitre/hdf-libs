// Package hdftocsafvex converts HDF Amendments to CSAF VEX (csaf_vex
// profile). Reverse direction of csaf-vex-to-hdf.
//
// The export is intentionally partial-fidelity by design. Fields the
// shared VEX mapping considers consumer-action-bearing survive round-trip;
// the rest (product taxonomy, threat granularity, full revision history)
// collapse into the available CSAF fields. See the converter README for
// the full round-trip table.
package hdftocsafvex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	"github.com/mitre/hdf-libs/hdf-converters/v3/shared/go/vex"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// cveIDPattern matches CVE identifiers. Only CVE-shaped requirementIds
// translate to CSAF VEX (the format is vulnerability-keyed).
var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// productsRegexp pulls product IDs back out of an HDF reason string
// previously written by csaf-vex-to-hdf. Best-effort — matches the
// 'Products: CSAFPID-0001, CSAFPID-0002' tail line.
var productsRegexp = regexp.MustCompile(`(?m)^Products:\s*(.+)$`)

// defaultProductID is used when an HDF override lacks both a componentRef
// and a recoverable product hint in the reason field.
const defaultProductID = "HDFPID-0001"

// CSAFVexDocument is the export envelope. Field shapes mirror the CSAF
// 2.0 schema closely enough that the output validates.
type CSAFVexDocument struct {
	Document        DocumentMeta    `json:"document"`
	ProductTree     ProductTree     `json:"product_tree"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type DocumentMeta struct {
	Category    string    `json:"category"`
	CSAFVersion string    `json:"csaf_version"`
	Title       string    `json:"title,omitempty"`
	Notes       []Note    `json:"notes,omitempty"`
	Publisher   Publisher `json:"publisher"`
	Tracking    Tracking  `json:"tracking"`
}

type Publisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type Tracking struct {
	ID                 string     `json:"id"`
	Status             string     `json:"status"`
	Version            string     `json:"version"`
	CurrentReleaseDate string     `json:"current_release_date"`
	InitialReleaseDate string     `json:"initial_release_date"`
	RevisionHistory    []Revision `json:"revision_history"`
	Generator          *Generator `json:"generator,omitempty"`
}

type Generator struct {
	Engine Engine `json:"engine"`
	Date   string `json:"date"`
}

type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Revision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type Note struct {
	Category string `json:"category"`
	Text     string `json:"text"`
	Title    string `json:"title,omitempty"`
}

type ProductTree struct {
	FullProductNames []FullProductName `json:"full_product_names"`
}

type FullProductName struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
}

// Score is a CSAF vulnerability score entry (one CVSS block + affected products).
type Score struct {
	Products []string  `json:"products"`
	CvssV2   *CvssData `json:"cvss_v2,omitempty"`
	CvssV3   *CvssData `json:"cvss_v3,omitempty"`
	CvssV4   *CvssData `json:"cvss_v4,omitempty"`
}

// CvssData is the CSAF representation of a CVSS block.
type CvssData struct {
	Version      string   `json:"version"`
	VectorString string   `json:"vectorString,omitempty"`
	BaseScore    *float64 `json:"baseScore,omitempty"`
	BaseSeverity string   `json:"baseSeverity,omitempty"`
}

// buildCsafScore maps an HDF Cvss block to a CSAF score entry (cvss_v2/v3/v4 by version).
func buildCsafScore(cvss *hdf.Cvss, products []string) *Score {
	if cvss == nil {
		return nil
	}
	ver := string(cvss.Version)
	data := &CvssData{Version: ver}
	if cvss.BaseVector != nil {
		data.VectorString = *cvss.BaseVector
	}
	if cvss.BaseScore != nil {
		data.BaseScore = cvss.BaseScore
	}
	if cvss.BaseSeverity != nil {
		data.BaseSeverity = string(*cvss.BaseSeverity)
	}
	if data.VectorString == "" && data.BaseScore == nil {
		return nil
	}
	score := &Score{Products: products}
	switch {
	case strings.HasPrefix(ver, "4"):
		score.CvssV4 = data
	case strings.HasPrefix(ver, "2"):
		score.CvssV2 = data
	default:
		score.CvssV3 = data
	}
	return score
}

type Vulnerability struct {
	CVE           string         `json:"cve"`
	Notes         []Note         `json:"notes,omitempty"`
	ProductStatus *ProductStatus `json:"product_status,omitempty"`
	Flags         []Flag         `json:"flags,omitempty"`
	Threats       []Threat       `json:"threats,omitempty"`
	Remediations  []Remediation  `json:"remediations,omitempty"`
	References    []Reference    `json:"references,omitempty"`
	Scores        []Score        `json:"scores,omitempty"`
}

type ProductStatus struct {
	Fixed            []string `json:"fixed,omitempty"`
	FirstFixed       []string `json:"first_fixed,omitempty"`
	KnownAffected    []string `json:"known_affected,omitempty"`
	KnownNotAffected []string `json:"known_not_affected,omitempty"`
}

type Flag struct {
	Label      string   `json:"label"`
	Date       string   `json:"date,omitempty"`
	ProductIDs []string `json:"product_ids"`
}

type Threat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type Remediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

type Reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url"`
}

// ConvertHDFToCSAFVEX parses HDF Amendments and emits a CSAF VEX document.
func ConvertHDFToCSAFVEX(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-csaf-vex", 0); err != nil {
		return nil, err
	}
	var amendments hdf.HDFAmendments
	if err := shared.DecodeHDF(input, &amendments); err != nil {
		return nil, fmt.Errorf("hdf-to-csaf-vex: parse HDF Amendments: %w", err)
	}

	doc := buildDocument(&amendments, earliestAppliedAt(&amendments), converterVersion)
	for _, group := range groupOverridesByCVE(amendments.Overrides) {
		v, ok := buildVulnerability(group)
		if !ok {
			continue
		}
		doc.Vulnerabilities = append(doc.Vulnerabilities, v)
		for _, pid := range group.productIDs() {
			doc.ProductTree.FullProductNames = appendUnique(doc.ProductTree.FullProductNames, pid)
		}
		for _, pid := range group.fixedProductIDs() {
			doc.ProductTree.FullProductNames = appendUnique(doc.ProductTree.FullProductNames, pid)
		}
	}
	// Global product-id sort so the product_tree order matches the TS exporter
	// (which sorts its product set) — otherwise multi-product docs diverge.
	sort.Slice(doc.ProductTree.FullProductNames, func(i, j int) bool {
		return doc.ProductTree.FullProductNames[i].ProductID < doc.ProductTree.FullProductNames[j].ProductID
	})

	if len(doc.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("hdf-to-csaf-vex: no overrides with CVE-shaped requirementIds; nothing to emit")
	}
	if len(doc.ProductTree.FullProductNames) == 0 {
		doc.ProductTree.FullProductNames = []FullProductName{{Name: defaultProductID, ProductID: defaultProductID}}
	}

	return marshalIndentPlain(doc)
}

// marshalIndentPlain serializes v with two-space indentation and without Go's
// default HTML escaping, so `<`, `>` and `&` survive as themselves — matching
// the TypeScript exporter's JSON.stringify output byte-for-byte.
func marshalIndentPlain(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// earliestAppliedAt derives a stable document time from the input: the earliest
// override appliedAt, falling back to now only when the input carries none.
func earliestAppliedAt(a *hdf.HDFAmendments) time.Time {
	t := time.Now().UTC()
	for i := range a.Overrides {
		applied := a.Overrides[i].AppliedAt
		if !applied.IsZero() && applied.Before(t) {
			t = applied
		}
	}
	return t
}

func buildDocument(a *hdf.HDFAmendments, docTime time.Time, converterVersion string) CSAFVexDocument {
	publisherName := "HDF Amendments Export"
	// CSAF requires publisher.namespace: a URL under the issuing party's control
	// serving as its globally unique identifier. This is a SAF/HDF tool export.
	publisherNamespace := "https://saf.mitre.org"
	if a.AppliedBy != nil && a.AppliedBy.Identifier != "" {
		publisherName = a.AppliedBy.Identifier
	}

	now := docTime.UTC().Format(time.RFC3339)
	trackingID := "HDF-VEX-EXPORT"
	if a.AmendmentID != nil && *a.AmendmentID != "" {
		trackingID = *a.AmendmentID
	}
	docVersion := "1"
	if a.Version != nil && *a.Version != "" {
		docVersion = *a.Version
	}

	title := a.Name
	if title == "" {
		title = "HDF Amendments exported as CSAF VEX"
	}

	notes := []Note{}
	if a.Description != nil && *a.Description != "" {
		notes = append(notes, Note{Category: "summary", Text: *a.Description, Title: "Description"})
	}

	return CSAFVexDocument{
		Document: DocumentMeta{
			Category:    "csaf_vex",
			CSAFVersion: "2.0",
			Title:       title,
			Notes:       notes,
			Publisher: Publisher{
				Category:  "other",
				Name:      publisherName,
				Namespace: publisherNamespace,
			},
			Tracking: Tracking{
				ID:                 trackingID,
				Status:             "final",
				Version:            docVersion,
				CurrentReleaseDate: now,
				InitialReleaseDate: now,
				RevisionHistory: []Revision{{
					Date:    now,
					Number:  docVersion,
					Summary: "Generated by hdf-to-csaf-vex from HDF Amendments.",
				}},
				Generator: &Generator{
					Engine: Engine{Name: "hdf-to-csaf-vex", Version: converterVersion},
					Date:   now,
				},
			},
		},
		ProductTree: ProductTree{FullProductNames: []FullProductName{}},
	}
}

// cveGroup collects every override that refers to the same CVE id.
type cveGroup struct {
	cve       string
	overrides []hdf.StandaloneOverride
}

func (g cveGroup) productIDs() []string {
	seen := map[string]bool{}
	var out []string
	for i := range g.overrides {
		for _, p := range productIDsFor(&g.overrides[i]) {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fixedProductIDs returns the synthesized fixed-version product ids across a
// group's affectedPackages, so they can be registered in the product_tree.
func (g cveGroup) fixedProductIDs() []string {
	var out []string
	for i := range g.overrides {
		for _, p := range g.overrides[i].AffectedPackages {
			if id, ok := vex.FixedPackageIdentifier(p); ok {
				out = append(out, id)
			}
		}
	}
	return out
}

// groupOverridesByCVE returns one group per CVE-shaped requirementId, in
// stable (sorted) CVE order so the output is deterministic. Non-CVE
// requirementIds are dropped — CSAF VEX is vulnerability-keyed.
func groupOverridesByCVE(overrides []hdf.StandaloneOverride) []cveGroup {
	groups := map[string]*cveGroup{}
	for i := range overrides {
		o := &overrides[i]
		if !cveIDPattern.MatchString(o.RequirementID) {
			continue
		}
		g, ok := groups[o.RequirementID]
		if !ok {
			g = &cveGroup{cve: o.RequirementID}
			groups[o.RequirementID] = g
		}
		g.overrides = append(g.overrides, *o)
	}
	out := make([]cveGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].cve < out[j].cve })
	return out
}

// buildVulnerability emits one CSAF VEX vulnerability from all overrides
// for a single CVE. The export logic is the inverse of import:
//
//   - justification set OR override type {falsePositive, attestation,
//     inherited} -> known_not_affected (+ flags[] when justification known)
//   - poam, milestones-complete + closure-chained -> fixed
//     (we never have closure-chained info in a one-shot export, so this
//     reduces to: poam with all milestones completed -> fixed)
//   - poam (otherwise), waiver, riskAdjustment, operationalRequirement
//     -> known_affected (+ threats[] from reason, + remediations[] from
//     poam milestones)
func buildVulnerability(group cveGroup) (Vulnerability, bool) {
	v := Vulnerability{CVE: group.cve}
	status := &ProductStatus{}
	var emittedAny bool

	for i := range group.overrides {
		o := &group.overrides[i]
		pids := productIDsFor(o)

		// Emit consumer-supplied CVSS enrichment as a CSAF score entry.
		if s := buildCsafScore(o.Cvss, pids); s != nil {
			v.Scores = append(v.Scores, *s)
			emittedAny = true
		}

		// Map each affectedPackages[].fixedInVersion to a distinct fixed-version
		// product referenced in product_status.first_fixed + a vendor_fix remediation.
		for j := range o.AffectedPackages {
			fixedID, ok := vex.FixedPackageIdentifier(o.AffectedPackages[j])
			if !ok {
				continue
			}
			status.FirstFixed = append(status.FirstFixed, fixedID)
			status.Fixed = append(status.Fixed, fixedID)
			v.Remediations = append(v.Remediations, Remediation{
				Category:   "vendor_fix",
				Details:    "Fixed in " + *o.AffectedPackages[j].FixedInVersion,
				ProductIDs: []string{fixedID},
			})
			emittedAny = true
		}

		canonical, ok := vex.ExportStatusFor(o, allMilestonesCompleted(o), false)
		if !ok {
			continue
		}

		// vex.ExportStatusFor returns Fixed only when closureChained is
		// true, which we cannot know from a one-shot export. Promote
		// poam-with-all-complete to Fixed here so single-document exports
		// still round-trip the obvious case.
		if o.Type == hdf.Poam && canonical == vex.StatusAffected && allMilestonesCompleted(o) {
			canonical = vex.StatusFixed
		}

		switch canonical {
		case vex.StatusNotAffected:
			status.KnownNotAffected = append(status.KnownNotAffected, pids...)
			if o.Justification != nil {
				v.Flags = append(v.Flags, Flag{
					Label:      string(*o.Justification),
					ProductIDs: pids,
					Date:       o.AppliedAt.UTC().Format(time.RFC3339),
				})
			}
			emittedAny = true
		case vex.StatusFixed:
			status.Fixed = append(status.Fixed, pids...)
			for _, m := range o.Milestones {
				if m.Description == "" {
					continue
				}
				v.Remediations = append(v.Remediations, Remediation{
					Category:   "vendor_fix",
					Details:    m.Description,
					ProductIDs: pids,
				})
			}
			emittedAny = true
		case vex.StatusAffected:
			status.KnownAffected = append(status.KnownAffected, pids...)
			if o.Reason != "" {
				v.Threats = append(v.Threats, Threat{
					Category:   "impact",
					Details:    stripProductsLine(o.Reason),
					ProductIDs: pids,
				})
			}
			// Open POA&Ms surface their milestone descriptions as
			// remediations so consumers see the planned action.
			if o.Type == hdf.Poam {
				for _, m := range o.Milestones {
					if m.Description == "" {
						continue
					}
					v.Remediations = append(v.Remediations, Remediation{
						Category:   "workaround",
						Details:    m.Description,
						ProductIDs: pids,
					})
				}
			}
			emittedAny = true
		}

		for _, e := range o.Evidence {
			if e.Type != hdf.URL || e.Data == "" {
				continue
			}
			desc := ""
			if e.Description != nil {
				desc = *e.Description
			}
			v.References = append(v.References, Reference{
				Category: "external",
				Summary:  desc,
				URL:      e.Data,
			})
		}
	}

	if !emittedAny {
		return Vulnerability{}, false
	}

	dedupeStrings(&status.Fixed)
	dedupeStrings(&status.FirstFixed)
	dedupeStrings(&status.KnownAffected)
	dedupeStrings(&status.KnownNotAffected)
	v.ProductStatus = status
	dedupeReferences(&v.References)
	return v, true
}

// allMilestonesCompleted returns true when every milestone on the override
// is in 'completed' state (and at least one exists). False for empty
// milestones — an empty POA&M is not closed.
func allMilestonesCompleted(o *hdf.StandaloneOverride) bool {
	if len(o.Milestones) == 0 {
		return false
	}
	for _, m := range o.Milestones {
		if m.Status != hdf.Completed {
			return false
		}
	}
	return true
}

// productIDsFor extracts product identifiers from an override. Preference
// order: structured affectedPackages (v3.2.x+ source of truth), then
// componentRef, then the legacy 'Products:' reason-line annotation
// (backward compat), then the default placeholder.
func productIDsFor(o *hdf.StandaloneOverride) []string {
	if len(o.AffectedPackages) > 0 {
		ids := make([]string, 0, len(o.AffectedPackages))
		for _, p := range o.AffectedPackages {
			if id, ok := vex.AffectedPackageToIdentifier(p); ok {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			return ids
		}
	}
	if o.ComponentRef != nil && *o.ComponentRef != "" {
		return []string{*o.ComponentRef}
	}
	if m := productsRegexp.FindStringSubmatch(o.Reason); len(m) > 1 {
		parts := strings.Split(m[1], ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{defaultProductID}
}

// stripProductsLine removes the 'Products: ...' tail line that csaf-vex
// import previously appended to reason — its content moves into
// product_status / product_tree on the export side, so emitting it as
// threat-impact prose too would duplicate the data.
func stripProductsLine(reason string) string {
	out := productsRegexp.ReplaceAllString(reason, "")
	return strings.TrimRight(out, "\n")
}

func appendUnique(in []FullProductName, productID string) []FullProductName {
	for _, e := range in {
		if e.ProductID == productID {
			return in
		}
	}
	return append(in, FullProductName{Name: productID, ProductID: productID})
}

func dedupeStrings(s *[]string) {
	if len(*s) <= 1 {
		return
	}
	seen := map[string]bool{}
	out := (*s)[:0]
	for _, v := range *s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	*s = out
}

func dedupeReferences(refs *[]Reference) {
	if len(*refs) <= 1 {
		return
	}
	seen := map[string]bool{}
	out := (*refs)[:0]
	for _, r := range *refs {
		if !seen[r.URL] {
			seen[r.URL] = true
			out = append(out, r)
		}
	}
	*refs = out
}
