// Package hdftoopenvex converts HDF Amendments to OpenVEX statements.
// Reverse direction of openvex-to-hdf.
//
// Intentionally partial-fidelity (Step 4f amendment-output pattern).
// Consumer-action-bearing fields (CVE id, status, justification) survive
// round-trip; the rest collapse into the available OpenVEX fields.
package hdftoopenvex

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

var cveIDPattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
var productsRegexp = regexp.MustCompile(`(?m)^Products:\s*(.+)$`)

const (
	openvexContext   = "https://openvex.dev/ns/v0.2.0"
	openvexNamespace = "https://openvex.dev/docs/public/"
	defaultProductID = "HDFPID-0001"
)

// Document is the OpenVEX top-level document.
type Document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Role       string      `json:"role,omitempty"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Tooling    string      `json:"tooling,omitempty"`
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
	StatusNotes     string        `json:"status_notes,omitempty"`
	Timestamp       string        `json:"timestamp,omitempty"`
}

// Vulnerability identifies a CVE.
type Vulnerability struct {
	ID   string `json:"@id,omitempty"`
	Name string `json:"name"`
}

// Product identifies a product the statement applies to.
type Product struct {
	ID string `json:"@id"`
}

// ConvertHDFToOpenVEX parses HDF Amendments and emits an OpenVEX
// document. One HDF override produces zero or more OpenVEX statements
// (one per CVE-shaped requirementId, grouping per status bucket).
func ConvertHDFToOpenVEX(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-openvex", 0); err != nil {
		return nil, err
	}
	var amendments hdf.HDFAmendments
	if err := shared.DecodeHDF(input, &amendments); err != nil {
		return nil, fmt.Errorf("hdf-to-openvex: parse HDF Amendments: %w", err)
	}

	// HDFAmendments has no document-level appliedAt; anchor the OpenVEX
	// timestamp on the earliest override.appliedAt when present.
	docTime := time.Now().UTC()
	for i := range amendments.Overrides {
		t := amendments.Overrides[i].AppliedAt
		if !t.IsZero() && (docTime.IsZero() || t.Before(docTime)) {
			docTime = t
		}
	}

	author := "HDF Amendments Export"
	role := ""
	if amendments.AppliedBy != nil && amendments.AppliedBy.Identifier != "" {
		author = amendments.AppliedBy.Identifier
		if amendments.AppliedBy.Description != nil {
			role = *amendments.AppliedBy.Description
		}
	}

	var statements []Statement
	for i := range amendments.Overrides {
		stmts := overrideToStatements(&amendments.Overrides[i], author)
		statements = append(statements, stmts...)
	}
	if len(statements) == 0 {
		return nil, fmt.Errorf("hdf-to-openvex: no overrides with CVE-shaped requirementIds; nothing to emit")
	}

	sort.SliceStable(statements, func(i, j int) bool {
		return statements[i].Vulnerability.Name < statements[j].Vulnerability.Name
	})

	doc := Document{
		Context:    openvexContext,
		ID:         buildDocumentID(input, &amendments),
		Author:     author,
		Role:       role,
		Timestamp:  docTime.UTC().Format(time.RFC3339),
		Version:    1,
		Tooling:    toolingFor(amendments.Generator),
		Statements: statements,
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

// overrideToStatements returns 0..1 OpenVEX statements for an override.
// Non-CVE requirementIds drop. operationalRequirement (no status/impact)
// drops. Other types map per the shared VEX helper.
func overrideToStatements(o *hdf.StandaloneOverride, docAuthor string) []Statement {
	if !cveIDPattern.MatchString(o.RequirementID) {
		return nil
	}

	canonical, ok := vex.ExportStatusFor(o, allMilestonesCompleted(o), false)
	if !ok {
		return nil
	}
	// Promote poam-with-all-complete to fixed even without closure chain
	// (single-shot export can't know the chain state).
	if o.Type == hdf.Poam && canonical == vex.StatusAffected && allMilestonesCompleted(o) {
		canonical = vex.StatusFixed
	}

	stmt := Statement{
		Vulnerability: Vulnerability{
			Name: o.RequirementID,
			ID:   "https://nvd.nist.gov/vuln/detail/" + o.RequirementID,
		},
		Status:    string(canonical),
		Timestamp: o.AppliedAt.UTC().Format(time.RFC3339),
		Products:  productsFor(o),
	}

	reason := stripProductsLine(o.Reason)
	reasonEmitted := false
	switch canonical {
	case vex.StatusNotAffected:
		if o.Justification != nil {
			stmt.Justification = string(*o.Justification)
		}
		stmt.ImpactStatement = reason
		reasonEmitted = reason != ""
	case vex.StatusFixed:
		stmt.ActionStatement = firstMilestoneAction(o)
		if stmt.ActionStatement == "" {
			stmt.ActionStatement = "Fix applied; consumer re-scan confirmed clean."
		}
	case vex.StatusAffected:
		// Open POA&M: the action_statement carries the planned remediation.
		// Waivers / risk adjustments / operationalRequirement: the reason
		// carries the rationale, which OpenVEX has no dedicated field for —
		// fold it into action_statement so it's not lost.
		stmt.ActionStatement = firstMilestoneAction(o)
		if stmt.ActionStatement == "" {
			stmt.ActionStatement = reason
			reasonEmitted = reason != ""
		}
	}

	stmt.StatusNotes = buildStatusNotes(o, reason, reasonEmitted, docAuthor)

	return []Statement{stmt}
}

// toolingFor renders the source amendments' generator (name + version) as the
// OpenVEX document-level `tooling` string ("expresses how the VEX document ...
// was generated"). Empty when the source carries no generator.
func toolingFor(g *hdf.Generator) string {
	if g == nil || g.Name == "" {
		return ""
	}
	if g.Version != "" {
		return g.Name + "/" + g.Version
	}
	return g.Name
}

// buildStatusNotes packs HDF override provenance that OpenVEX has no dedicated
// field for into the statement's free-text `status_notes`: the governing
// override type (7 HDF types collapse to 4 VEX statuses), the override reason
// when it was not already surfaced in impact_statement/action_statement, a
// per-override author that diverges from the document author, evidence
// references, and milestone metadata (status + estimated completion) that
// action_statement alone cannot carry.
func buildStatusNotes(o *hdf.StandaloneOverride, reason string, reasonEmitted bool, docAuthor string) string {
	notes := []string{"HDF override type: " + string(o.Type)}
	if !reasonEmitted && reason != "" {
		notes = append(notes, "Reason: "+reason)
	}
	if o.AppliedBy.Identifier != "" && o.AppliedBy.Identifier != docAuthor {
		notes = append(notes, "Applied by: "+o.AppliedBy.Identifier)
	}
	for _, e := range o.Evidence {
		notes = append(notes, formatEvidence(e))
	}
	for _, m := range o.Milestones {
		notes = append(notes, formatMilestone(m))
	}
	return strings.Join(notes, "\n")
}

func formatEvidence(e hdf.Evidence) string {
	desc := ""
	if e.Description != nil {
		desc = *e.Description
	}
	if desc != "" {
		return fmt.Sprintf("Evidence (%s): %s (%s)", e.Type, desc, e.Data)
	}
	return fmt.Sprintf("Evidence (%s): %s", e.Type, e.Data)
}

func formatMilestone(m hdf.Milestone) string {
	var meta []string
	if m.Status != "" {
		meta = append(meta, "status: "+string(m.Status))
	}
	if !m.EstimatedCompletion.IsZero() {
		meta = append(meta, "estimated completion: "+m.EstimatedCompletion.UTC().Format(time.RFC3339))
	}
	label := "Milestone"
	if m.Description != "" {
		label = "Milestone: " + m.Description
	}
	if len(meta) == 0 {
		return label
	}
	return label + " (" + strings.Join(meta, ", ") + ")"
}

func productsFor(o *hdf.StandaloneOverride) []Product {
	// Structured affectedPackages is the source of truth (v3.2.x and later).
	if len(o.AffectedPackages) > 0 {
		ids := make([]string, 0, len(o.AffectedPackages))
		for _, p := range o.AffectedPackages {
			if id, ok := vex.AffectedPackageToIdentifier(p); ok {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			out := make([]Product, 0, len(ids))
			for _, id := range ids {
				out = append(out, Product{ID: id})
			}
			return out
		}
	}
	// Backward-compat fallbacks for pre-affectedPackages HDF inputs.
	var ids []string
	if o.ComponentRef != nil && *o.ComponentRef != "" {
		ids = []string{*o.ComponentRef}
	} else if m := productsRegexp.FindStringSubmatch(o.Reason); len(m) > 1 {
		for _, p := range strings.Split(m[1], ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				ids = append(ids, p)
			}
		}
	}
	if len(ids) == 0 {
		ids = []string{defaultProductID}
	}
	out := make([]Product, 0, len(ids))
	for _, id := range ids {
		out = append(out, Product{ID: id})
	}
	return out
}

func firstMilestoneAction(o *hdf.StandaloneOverride) string {
	for _, m := range o.Milestones {
		if m.Description != "" {
			return m.Description
		}
	}
	return ""
}

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

// stripProductsLine removes the 'Products: ...' tail that openvex-to-hdf
// imports append; the product info now lives in statement.products[].
func stripProductsLine(reason string) string {
	return strings.TrimRight(productsRegexp.ReplaceAllString(reason, ""), "\n")
}

// buildDocumentID synthesizes a stable OpenVEX @id from the input bytes.
// Stable so the same input produces the same id; deterministic for tests.
func buildDocumentID(input []byte, a *hdf.HDFAmendments) string {
	if a.AmendmentID != nil && *a.AmendmentID != "" {
		return openvexNamespace + "vex-" + *a.AmendmentID
	}
	sum := sha256.Sum256(input)
	return openvexNamespace + "vex-" + hex.EncodeToString(sum[:])
}
