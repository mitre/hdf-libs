// Package hdftocyclonedxvex converts HDF Amendments to CycloneDX BOMs
// carrying VEX analysis statements. Reverse direction of
// cyclonedx-vex-to-hdf.
//
// Partial-fidelity by design (Step 4f). The emitted BOM is a minimal
// CycloneDX envelope: metadata + components[] + one vulnerability per
// CVE-shaped requirementId. Non-CVE overrides drop. Evidence URLs are
// preserved as vulnerability.references; reason prose (after stripping
// import-side annotation lines) lands in analysis.detail.
package hdftocyclonedxvex

import (
	"bytes"
	"crypto/sha256"
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

var (
	cveIDPattern   = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	productsRegexp = regexp.MustCompile(`(?m)^Products:\s*(.+)$`)
	rawJustRegexp  = regexp.MustCompile(`(?m)^VEX justification:\s*(.+)$`)
	responseRegexp = regexp.MustCompile(`(?m)^Response:.*$`)
)

const defaultProductID = "HDFPID-0001"

// BOM is the CycloneDX top-level document we emit.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        Metadata        `json:"metadata"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Metadata struct {
	Timestamp string   `json:"timestamp"`
	Tools     []Tool   `json:"tools,omitempty"`
	Authors   []Author `json:"authors,omitempty"`
}

type Tool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

type Author struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type Component struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	BOMRef  string `json:"bom-ref"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
	Cpe     string `json:"cpe,omitempty"`
}

// Rating is a CycloneDX vulnerability rating (a CVSS score).
type Rating struct {
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Method   string   `json:"method,omitempty"`
	Vector   string   `json:"vector,omitempty"`
}

// buildCdxRating maps an HDF Cvss block to a CycloneDX rating.
func buildCdxRating(cvss *hdf.Cvss) *Rating {
	if cvss == nil {
		return nil
	}
	rating := &Rating{}
	if cvss.BaseScore != nil {
		rating.Score = cvss.BaseScore
	}
	if cvss.BaseSeverity != nil {
		rating.Severity = string(*cvss.BaseSeverity)
	}
	if cvss.BaseVector != nil {
		rating.Vector = *cvss.BaseVector
	}
	switch string(cvss.Version) {
	case "4.0":
		rating.Method = "CVSSv4"
	case "3.1":
		rating.Method = "CVSSv31"
	case "3.0":
		rating.Method = "CVSSv3"
	case "2.0":
		rating.Method = "CVSSv2"
	default:
		rating.Method = "other"
	}
	if rating.Score == nil && rating.Vector == "" {
		return nil
	}
	return rating
}

type Vulnerability struct {
	ID             string        `json:"id"`
	Source         *Source       `json:"source,omitempty"`
	References     []Reference   `json:"references,omitempty"`
	Ratings        []Rating      `json:"ratings,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	Analysis       Analysis      `json:"analysis"`
	Affects        []AffectedRef `json:"affects"`
}

type Source struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
}

type Reference struct {
	ID     string `json:"id"`
	Source Source `json:"source"`
}

type Analysis struct {
	State         string   `json:"state"`
	Justification string   `json:"justification,omitempty"`
	Response      []string `json:"response,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type AffectedRef struct {
	Ref      string       `json:"ref"`
	Versions []CdxVersion `json:"versions,omitempty"`
}

type CdxVersion struct {
	Version string `json:"version,omitempty"`
	Range   string `json:"range,omitempty"`
	Status  string `json:"status"`
}

// ConvertHDFToCycloneDXVEX parses HDF Amendments and emits a CycloneDX
// BOM with VEX analysis statements.
func ConvertHDFToCycloneDXVEX(input []byte, converterVersion string) ([]byte, error) {
	if err := shared.ValidateJSONSize(input, "hdf-to-cyclonedx-vex", 0); err != nil {
		return nil, err
	}
	var amendments hdf.HDFAmendments
	if err := shared.DecodeHDF(input, &amendments); err != nil {
		return nil, fmt.Errorf("hdf-to-cyclonedx-vex: parse HDF Amendments: %w", err)
	}

	componentRegistry := map[string]Component{}
	var vulnerabilities []Vulnerability
	for i := range amendments.Overrides {
		o := &amendments.Overrides[i]
		if !cveIDPattern.MatchString(o.RequirementID) {
			continue
		}
		v, ok := overrideToVulnerability(o, componentRegistry)
		if !ok {
			continue
		}
		vulnerabilities = append(vulnerabilities, v)
	}
	if len(vulnerabilities) == 0 {
		return nil, fmt.Errorf("hdf-to-cyclonedx-vex: no overrides with CVE-shaped requirementIds; nothing to emit")
	}

	sort.Slice(vulnerabilities, func(i, j int) bool { return vulnerabilities[i].ID < vulnerabilities[j].ID })

	components := componentsFromRegistry(componentRegistry)
	sort.Slice(components, func(i, j int) bool { return components[i].BOMRef < components[j].BOMRef })

	docTime := earliestAppliedAt(&amendments)

	bom := BOM{
		BOMFormat:       "CycloneDX",
		SpecVersion:     "1.4",
		SerialNumber:    buildSerialNumber(input, &amendments),
		Version:         1,
		Metadata:        buildMetadata(&amendments, docTime, converterVersion),
		Components:      components,
		Vulnerabilities: vulnerabilities,
	}
	return marshalIndentPlain(bom)
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

func overrideToVulnerability(o *hdf.StandaloneOverride, componentRegistry map[string]Component) (Vulnerability, bool) {
	canonical, ok := vex.ExportStatusFor(o, allMilestonesCompleted(o), false)
	if !ok {
		return Vulnerability{}, false
	}
	// Single-shot exports can't see the closure-amendment chain, so the
	// shared helper conservatively returns Affected for completed POA&Ms.
	// Promote when every milestone is completed — the obvious case.
	if o.Type == hdf.Poam && canonical == vex.StatusAffected && allMilestonesCompleted(o) {
		canonical = vex.StatusFixed
	}

	state := canonicalToCycloneDXState(canonical)
	pids := productIDsFor(o)
	// Pair each emitted product id back to the AffectedPackage it came
	// from so the CycloneDX component preserves name/version/purl/cpe.
	// Falls back to a pid-only component for legacy paths (componentRef
	// or 'Products:' reason annotation).
	pkgByID := make(map[string]hdf.AffectedPackage, len(o.AffectedPackages))
	for _, p := range o.AffectedPackages {
		if id, ok := vex.AffectedPackageToIdentifier(p); ok {
			pkgByID[id] = p
		}
	}
	for _, pid := range pids {
		pkg, ok := pkgByID[pid]
		if ok {
			componentRegistry[pid] = componentFromAffectedPackage(pid, pkg)
		} else {
			componentRegistry[pid] = componentFor(pid)
		}
	}

	analysis := Analysis{State: state}
	// The HDF Justification enum uses long-form names (component_not_present
	// etc.) drawn from OpenVEX/CSAF; CycloneDX uses short-form names
	// (code_not_present, code_not_reachable, protected_by_mitigating_control)
	// for the same concepts. Translate via the shared helper.
	if o.Justification != nil {
		if v, ok := vex.JustificationForCycloneDX(*o.Justification); ok {
			analysis.Justification = v
		}
	}
	if detail := stripReasonAnnotations(o.Reason); detail != "" {
		analysis.Detail = detail
	}
	switch canonical {
	case vex.StatusFixed:
		analysis.Response = []string{"update"}
	case vex.StatusAffected:
		if o.Type == hdf.Poam {
			analysis.Response = []string{"workaround_available"}
		}
	}

	v := Vulnerability{
		ID:       o.RequirementID,
		Source:   &Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + o.RequirementID},
		Analysis: analysis,
		Affects:  affectsForProducts(pids, pkgByID),
	}

	// Emit consumer-supplied CVSS enrichment as a CycloneDX rating.
	if rating := buildCdxRating(o.Cvss); rating != nil {
		v.Ratings = append(v.Ratings, *rating)
	}

	// A fixedInVersion we could not express as a vers range (no ecosystem/purl
	// to key the range) becomes a free-text recommendation instead.
	for i := range o.AffectedPackages {
		p := o.AffectedPackages[i]
		if p.FixedInVersion == nil || *p.FixedInVersion == "" {
			continue
		}
		if _, ok := vex.VersTypeFor(p); !ok {
			v.Recommendation = "Upgrade to " + *p.FixedInVersion
			break
		}
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
			ID:     o.RequirementID,
			Source: Source{Name: desc, URL: e.Data},
		})
	}

	return v, true
}

// canonicalToCycloneDXState maps the shared helper's status enum to a
// CycloneDX analysis.state string. CycloneDX uses `resolved` (not
// `fixed`) and `exploitable` (not `affected`).
func canonicalToCycloneDXState(canonical vex.Status) string {
	switch canonical {
	case vex.StatusNotAffected:
		return "not_affected"
	case vex.StatusFixed:
		return "resolved"
	case vex.StatusAffected:
		return "exploitable"
	}
	return string(canonical)
}

func componentFor(pid string) Component {
	c := Component{Type: "application", Name: pid, BOMRef: pid}
	if strings.HasPrefix(pid, "pkg:") {
		c.Purl = pid
	} else if strings.HasPrefix(pid, "cpe:2.3:") {
		c.Cpe = pid
	}
	return c
}

func componentFromAffectedPackage(pid string, pkg hdf.AffectedPackage) Component {
	c := Component{Type: "application", BOMRef: pid}
	if pkg.Name != nil && *pkg.Name != "" {
		c.Name = *pkg.Name
	} else {
		c.Name = pid
	}
	if pkg.Version != nil && *pkg.Version != "" {
		c.Version = *pkg.Version
	}
	if pkg.Purl != nil && *pkg.Purl != "" {
		c.Purl = *pkg.Purl
	} else if strings.HasPrefix(pid, "pkg:") {
		c.Purl = pid
	}
	if pkg.Cpe != nil && *pkg.Cpe != "" {
		c.Cpe = *pkg.Cpe
	} else if strings.HasPrefix(pid, "cpe:2.3:") {
		c.Cpe = pid
	}
	return c
}

func componentsFromRegistry(reg map[string]Component) []Component {
	out := make([]Component, 0, len(reg))
	for _, c := range reg {
		out = append(out, c)
	}
	return out
}

func productIDsFor(o *hdf.StandaloneOverride) []string {
	// Structured affectedPackages is the source of truth (v3.2.x and later).
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
	// Backward-compat fallbacks for pre-affectedPackages HDF inputs.
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

func affectsForProducts(pids []string, pkgByID map[string]hdf.AffectedPackage) []AffectedRef {
	out := make([]AffectedRef, 0, len(pids))
	for _, p := range pids {
		ref := AffectedRef{Ref: p}
		if pkg, ok := pkgByID[p]; ok {
			ref.Versions = buildCdxAffectsVersions(pkg)
		}
		out = append(out, ref)
	}
	return out
}

// buildCdxAffectsVersions renders affects[].versions[] for a package with a
// fixedInVersion: the current version is `affected`, and `>= fixedInVersion`
// is `unaffected`, expressed as a vers range. Returns nil when there is no
// vers type to key the range (caller falls back to a free-text recommendation).
func buildCdxAffectsVersions(pkg hdf.AffectedPackage) []CdxVersion {
	if pkg.FixedInVersion == nil || *pkg.FixedInVersion == "" {
		return nil
	}
	t, ok := vex.VersTypeFor(pkg)
	if !ok {
		return nil
	}
	var versions []CdxVersion
	if pkg.Version != nil && *pkg.Version != "" {
		versions = append(versions, CdxVersion{Version: *pkg.Version, Status: "affected"})
	}
	versions = append(versions, CdxVersion{Range: "vers:" + t + "/>=" + *pkg.FixedInVersion, Status: "unaffected"})
	return versions
}

// stripReasonAnnotations removes the 'Products: …' tail line that
// import-side converters append, so analysis.detail carries only the
// prose. (The 'VEX justification:' and 'Response:' annotations were
// removed when the Justification enum was extended to cover the full
// CycloneDX vocabulary; this stripper also handles any legacy reason
// strings that still carry them.)
func stripReasonAnnotations(reason string) string {
	out := productsRegexp.ReplaceAllString(reason, "")
	out = rawJustRegexp.ReplaceAllString(out, "")
	out = responseRegexp.ReplaceAllString(out, "")
	return strings.TrimSpace(out)
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

func buildMetadata(a *hdf.HDFAmendments, docTime time.Time, converterVersion string) Metadata {
	m := Metadata{
		Timestamp: docTime.Format(time.RFC3339),
		Tools: []Tool{{
			Vendor:  "mitre",
			Name:    "hdf-to-cyclonedx-vex",
			Version: converterVersion,
		}},
	}
	if a.AppliedBy != nil && a.AppliedBy.Identifier != "" {
		author := Author{Name: a.AppliedBy.Identifier}
		if a.AppliedBy.Type == hdf.Email {
			author.Email = a.AppliedBy.Identifier
			author.Name = ""
		}
		m.Authors = append(m.Authors, author)
	}
	return m
}

func buildSerialNumber(input []byte, a *hdf.HDFAmendments) string {
	if a.AmendmentID != nil && *a.AmendmentID != "" {
		return "urn:uuid:" + *a.AmendmentID
	}
	// CycloneDX serialNumber must be an RFC 4122 urn:uuid. Derive a
	// deterministic name-based (v5-style) UUID from the input hash: take the
	// first 16 bytes and set the version (5) and variant bits so strict UUID
	// parsers accept it.
	b := sha256.Sum256(input)
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
