package xccdf

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Completeness of the benchmark path against the XCCDF schemas: every element
// and attribute path the 1.1.4 and 1.2 XSDs admit under Benchmark, Group and
// Rule is mapped to a Baseline field or skipped with a reason in
// fixtures/xccdf-coverage.json, which the TypeScript suite reads too. The walker
// reads the XSDs as plain XML and resolves only the constructs these two use.

const xmlSchemaNS = "http://www.w3.org/2001/XMLSchema"

// xccdfCoverageRoots are walked as their own path roots; a reference to one
// from a parent records the element path and does not descend.
var xccdfCoverageRoots = []string{"Benchmark", "Group", "Rule"}

// xsdNode is the generic element view of a schema document.
type xsdNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Children []*xsdNode `xml:",any"`
}

func (n *xsdNode) attr(name string) string {
	for _, a := range n.Attrs {
		if a.Name.Local == name && a.Name.Space == "" {
			return a.Value
		}
	}
	return ""
}

// Facets carry no element or attribute paths, so a restriction's facets are
// passed over; every other schema construct the walker does not model is
// reported, so a construct outside its rules fails the test instead of
// silently dropping paths.
var xsdIgnoredConstructs = map[string]bool{
	"annotation": true, "enumeration": true, "pattern": true, "length": true,
	"minLength": true, "maxLength": true, "minInclusive": true, "maxInclusive": true,
	"minExclusive": true, "maxExclusive": true, "totalDigits": true,
	"fractionDigits": true, "whiteSpace": true,
}

type xsdWalker struct {
	targetNS    string
	nsByPrefix  map[string]string
	types       map[string]*xsdNode
	elements    map[string]*xsdNode
	roots       map[string]bool
	paths       map[string]bool
	unsupported []string
}

func newXsdWalker(schema *xsdNode, roots []string) *xsdWalker {
	w := &xsdWalker{
		nsByPrefix: map[string]string{},
		types:      map[string]*xsdNode{},
		elements:   map[string]*xsdNode{},
		roots:      map[string]bool{},
		paths:      map[string]bool{},
	}
	for _, a := range schema.Attrs {
		switch {
		case a.Name.Space == "xmlns":
			w.nsByPrefix[a.Name.Local] = a.Value
		case a.Name.Space == "" && a.Name.Local == "xmlns":
			w.nsByPrefix[""] = a.Value
		case a.Name.Space == "" && a.Name.Local == "targetNamespace":
			w.targetNS = a.Value
		}
	}
	for _, c := range schema.Children {
		if c.XMLName.Space != xmlSchemaNS {
			continue
		}
		switch c.XMLName.Local {
		case "complexType", "simpleType":
			w.types[c.attr("name")] = c
		case "element":
			w.elements[c.attr("name")] = c
		}
	}
	for _, r := range roots {
		w.roots[r] = true
	}
	return w
}

// resolve splits a qualified reference into its local name and whether it
// names something in this schema's own namespace (as opposed to a built-in
// XML Schema type or an imported namespace).
func (w *xsdWalker) resolve(qname string) (local string, own bool) {
	prefix, local, found := strings.Cut(qname, ":")
	if !found {
		return qname, w.nsByPrefix[""] == w.targetNS
	}
	return local, w.nsByPrefix[prefix] == w.targetNS
}

func (w *xsdWalker) walkRoot(name string) {
	el := w.elements[name]
	if el == nil {
		w.unsupported = append(w.unsupported, "no global element named "+name)
		return
	}
	w.walkElementContent(el, name, map[string]bool{})
}

func (w *xsdWalker) walkElementContent(el *xsdNode, path string, stack map[string]bool) {
	if tn := el.attr("type"); tn != "" {
		w.walkNamedType(tn, path, stack)
		return
	}
	for _, c := range el.Children {
		if c.XMLName.Space == xmlSchemaNS && c.XMLName.Local == "complexType" {
			w.walkType(c, path, stack)
		}
	}
}

// walkNamedType follows a type reference. Built-in and imported types carry
// no paths of this schema; a type already on the stack is the complex-check
// recursion, whose element path is recorded and whose content repeats its
// parent's, so descent stops there.
func (w *xsdWalker) walkNamedType(qname, path string, stack map[string]bool) {
	local, own := w.resolve(qname)
	if !own {
		return
	}
	t := w.types[local]
	if t == nil {
		w.unsupported = append(w.unsupported, "unresolved type "+qname+" at "+path)
		return
	}
	if t.XMLName.Local != "complexType" || stack[local] {
		return
	}
	stack[local] = true
	w.walkType(t, path, stack)
	delete(stack, local)
}

func (w *xsdWalker) walkType(t *xsdNode, path string, stack map[string]bool) {
	for _, c := range t.Children {
		if c.XMLName.Space != xmlSchemaNS {
			continue
		}
		switch c.XMLName.Local {
		case "sequence", "choice", "all", "complexContent", "simpleContent":
			w.walkType(c, path, stack)
		case "extension", "restriction":
			if base := c.attr("base"); base != "" {
				w.walkNamedType(base, path, stack)
			}
			w.walkType(c, path, stack)
		case "attribute":
			name := c.attr("name")
			if name == "" {
				name, _ = w.resolve(c.attr("ref"))
			}
			w.paths[path+"/@"+name] = true
		case "anyAttribute":
			w.paths[path+"/@*"] = true
		case "any":
			w.paths[path+"/*"] = true
		case "element":
			w.walkElement(c, path, stack)
		default:
			if !xsdIgnoredConstructs[c.XMLName.Local] {
				w.unsupported = append(w.unsupported, "xsd:"+c.XMLName.Local+" at "+path)
			}
		}
	}
}

func (w *xsdWalker) walkElement(el *xsdNode, path string, stack map[string]bool) {
	name := el.attr("name")
	target := el
	if ref := el.attr("ref"); ref != "" {
		local, own := w.resolve(ref)
		name = local
		target = nil
		if own {
			target = w.elements[local]
			if target == nil {
				w.unsupported = append(w.unsupported, "unresolved element ref "+ref+" at "+path)
			}
		}
	}
	p := path + "/" + name
	w.paths[p] = true
	if target == nil || w.roots[name] {
		return
	}
	w.walkElementContent(target, p, stack)
}

func xccdfSchemaPath(name string) string {
	return filepath.Join(shared.GetConvertersDir(), "hdf-to-xccdf", "schemas", name)
}

// walkXccdfSchemas returns the sorted union of the paths both schemas admit
// under the coverage roots.
func walkXccdfSchemas(t *testing.T) []string {
	t.Helper()
	union := map[string]bool{}
	for _, name := range []string{"xccdf-1.1.4.xsd", "xccdf_1.2.xsd"} {
		data, err := os.ReadFile(xccdfSchemaPath(name))
		require.NoError(t, err)
		var schema xsdNode
		require.NoError(t, xml.Unmarshal(data, &schema))
		w := newXsdWalker(&schema, xccdfCoverageRoots)
		for _, root := range xccdfCoverageRoots {
			w.walkRoot(root)
		}
		require.Empty(t, w.unsupported, "%s uses a construct the walker does not resolve", name)
		for p := range w.paths {
			union[p] = true
		}
	}
	paths := make([]string, 0, len(union))
	for p := range union {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// coverageTargets accepts "target": "tags.cce" and
// "target": ["requirement.id", "tags.rid"].
type coverageTargets []string

func (c *coverageTargets) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*c = coverageTargets{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return fmt.Errorf("target must be a string or a list of strings, got %s", b)
	}
	*c = many
	return nil
}

type coverageRow struct {
	Target  coverageTargets `json:"target"`
	Reason  string          `json:"reason,omitempty"`
	Fixture string          `json:"fixture,omitempty"`
}

// coverageSchemaPaths pins the walker's whole output, so the Go and
// TypeScript walkers cannot drift apart inside a subtree row: the path count
// and the SHA-256 of the sorted paths joined by newlines.
type coverageSchemaPaths struct {
	Count  int    `json:"count"`
	SHA256 string `json:"sha256"`
}

// coverageAllowlist is fixtures/xccdf-coverage.json: paths keyed in the
// walker's output form (a key ending in /** covers the paths below it), and
// vendor rows for content the schemas leave opaque, keyed by a schema path
// extended with the vendor's own elements or a [@attr=value] selector.
type coverageAllowlist struct {
	Comment     string                 `json:"$comment,omitempty"`
	SchemaPaths coverageSchemaPaths    `json:"schemaPaths"`
	Paths       map[string]coverageRow `json:"paths"`
	Vendor      map[string]coverageRow `json:"vendor"`
}

func schemaPathsDigest(paths []string) string {
	sum := sha256.Sum256([]byte(strings.Join(paths, "\n") + "\n"))
	return hex.EncodeToString(sum[:])
}

func decodeCoverageAllowlist(data []byte) (coverageAllowlist, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var allow coverageAllowlist
	err := dec.Decode(&allow)
	return allow, err
}

func loadCoverageAllowlist(t *testing.T) coverageAllowlist {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(shared.GetConvertersDir(), "xccdf-results-to-hdf", "fixtures", "xccdf-coverage.json"))
	require.NoError(t, err)
	allow, err := decodeCoverageAllowlist(data)
	require.NoError(t, err)
	return allow
}

// Targets name where a source value lands in the Baseline: the document, a
// requirement, a group, a tag, a description label, extensions.passthrough,
// refs, or the requirements/groups a container element becomes.
var coverageTargetForm = regexp.MustCompile(`^(skip|refs|requirements|groups|(document|requirement|groups|tags|descriptions|passthrough)\.[A-Za-z][A-Za-z0-9_]*)$`)

var coveragePredicate = regexp.MustCompile(`\[[^\]]*\]`)

func sortedCoverageKeys(rows map[string]coverageRow) []string {
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// coverageProblems reports every way the walked paths and the allowlist
// disagree, in sorted order, so the failing test names the first offender.
func coverageProblems(walked []string, allow coverageAllowlist) []string {
	walkedSet := map[string]bool{}
	for _, p := range walked {
		walkedSet[p] = true
	}
	var subtrees []string
	for key := range allow.Paths {
		if prefix, isSubtree := strings.CutSuffix(key, "/**"); isSubtree {
			subtrees = append(subtrees, prefix)
		}
	}
	sort.Strings(subtrees)
	under := func(p, prefix string) bool { return strings.HasPrefix(p, prefix+"/") }

	var problems []string
	for _, p := range walked {
		if _, listed := allow.Paths[p]; listed {
			continue
		}
		covered := false
		for _, prefix := range subtrees {
			if under(p, prefix) {
				covered = true
				break
			}
		}
		if !covered {
			problems = append(problems, "schema path not in the allowlist: "+p)
		}
	}
	for _, key := range sortedCoverageKeys(allow.Paths) {
		if prefix, isSubtree := strings.CutSuffix(key, "/**"); isSubtree {
			defined := false
			for _, p := range walked {
				if under(p, prefix) {
					defined = true
					break
				}
			}
			if !defined {
				problems = append(problems, "allowlist subtree defined by no schema: "+key)
			}
			continue
		}
		if !walkedSet[key] {
			problems = append(problems, "allowlist path defined by no schema: "+key)
		}
		for _, prefix := range subtrees {
			if under(key, prefix) {
				problems = append(problems, "exact row shadowed by subtree row "+prefix+"/**: "+key)
			}
		}
	}
	for _, key := range sortedCoverageKeys(allow.Vendor) {
		base := coveragePredicate.ReplaceAllString(key, "")
		switch {
		case base != key:
			if !walkedSet[base] {
				problems = append(problems, "vendor selector on a path no schema defines: "+key)
			}
		case walkedSet[key]:
			problems = append(problems, "vendor path is schema-defined and belongs in paths: "+key)
		default:
			ancestor := false
			for i := strings.LastIndex(key, "/"); i > 0; i = strings.LastIndex(key[:i], "/") {
				if walkedSet[key[:i]] {
					ancestor = true
					break
				}
			}
			if !ancestor {
				problems = append(problems, "vendor path has no schema-defined ancestor: "+key)
			}
		}
	}
	for _, section := range []map[string]coverageRow{allow.Paths, allow.Vendor} {
		for _, key := range sortedCoverageKeys(section) {
			row := section[key]
			if len(row.Target) == 0 {
				problems = append(problems, "row without a target: "+key)
				continue
			}
			skip := false
			for _, target := range row.Target {
				if !coverageTargetForm.MatchString(target) {
					problems = append(problems, "row with an unknown target form: "+key+" -> "+target)
				}
				skip = skip || target == "skip"
			}
			if skip && len(row.Target) > 1 {
				problems = append(problems, "skip combined with another target: "+key)
			}
			if skip && row.Reason == "" {
				problems = append(problems, "skip row without a reason: "+key)
			}
		}
	}
	return problems
}

// nonEmptyValue is "non-empty" for a tag or passthrough value: a string with
// text, a list or map with members, or a bool or number, which is present by
// being there. An unexpected type is not arrived, so it fails visibly.
func nonEmptyValue(v any) bool {
	switch x := v.(type) {
	case string:
		return x != ""
	case []string:
		return len(x) > 0
	case []any:
		return len(x) > 0
	case []map[string]any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	case bool, float64, int:
		return true
	default:
		return false
	}
}

func nonEmptyPtr(s *string) bool {
	return s != nil && *s != ""
}

func anyRequirement(b *hdf.HDFBaseline, holds func(r *hdf.BaselineRequirement) bool) bool {
	for i := range b.Requirements {
		if holds(&b.Requirements[i]) {
			return true
		}
	}
	return false
}

// targetArrives reports whether the Baseline carries a non-empty value at a
// coverage target. The converter's output decides, never the input. Impact is
// numeric and present by schema, so it counts as arrived when above zero.
func targetArrives(b *hdf.HDFBaseline, target string) bool {
	section, field, _ := strings.Cut(target, ".")
	switch section {
	case "requirements":
		return field == "" && len(b.Requirements) > 0
	case "groups":
		switch field {
		case "":
			return len(b.Groups) > 0
		case "id":
			for _, g := range b.Groups {
				if g.ID != "" {
					return true
				}
			}
		case "title":
			for _, g := range b.Groups {
				if nonEmptyPtr(g.Title) {
					return true
				}
			}
		}
		return false
	case "document":
		switch field {
		case "name":
			return b.Name != ""
		case "title":
			return nonEmptyPtr(b.Title)
		case "version":
			return nonEmptyPtr(b.Version)
		case "summary":
			return nonEmptyPtr(b.Summary)
		}
		return false
	case "requirement":
		switch field {
		case "id":
			return anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return r.ID != "" })
		case "title":
			return anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return nonEmptyPtr(r.Title) })
		case "impact":
			return anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return r.Impact > 0 })
		case "severity":
			return anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return r.Severity != nil && *r.Severity != "" })
		}
		return false
	case "tags":
		return field != "" && anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return nonEmptyValue(r.Tags[field]) })
	case "descriptions":
		return field != "" && anyRequirement(b, func(r *hdf.BaselineRequirement) bool {
			for _, d := range r.Descriptions {
				if d.Label == field && d.Data != "" {
					return true
				}
			}
			return false
		})
	case "refs":
		return field == "" && anyRequirement(b, func(r *hdf.BaselineRequirement) bool { return len(r.Refs) > 0 })
	case "passthrough":
		return field != "" && b.Extensions != nil && nonEmptyValue(b.Extensions.Passthrough[field])
	}
	return false
}

type baselineLoader func(fixture string) (*hdf.HDFBaseline, error)

// arrivalProblems is the second half of the completeness test: every mapped
// row names a fixture, that fixture converts, and every target of the row
// arrives non-empty. Rows marked "none: <reason>" are returned as skipped so
// the test lists them by name instead of passing them silently.
func arrivalProblems(allow coverageAllowlist, load baselineLoader) (problems, skipped []string) {
	for _, section := range []map[string]coverageRow{allow.Paths, allow.Vendor} {
		for _, key := range sortedCoverageKeys(section) {
			row := section[key]
			if slices.Contains(row.Target, "skip") {
				if row.Fixture != "" {
					problems = append(problems, "skip row names a fixture: "+key)
				}
				continue
			}
			reason, isNone := strings.CutPrefix(row.Fixture, "none:")
			switch {
			case row.Fixture == "":
				problems = append(problems, "mapped row without a fixture: "+key)
			case isNone:
				if reason = strings.TrimSpace(reason); reason == "" {
					problems = append(problems, "fixture: none without a reason: "+key)
				} else {
					skipped = append(skipped, key+": "+reason)
				}
			default:
				b, err := load(row.Fixture)
				if err != nil {
					problems = append(problems, fmt.Sprintf("fixture %s for %s: %v", row.Fixture, key, err))
					continue
				}
				for _, target := range row.Target {
					if !targetArrives(b, target) {
						problems = append(problems, fmt.Sprintf("target %s does not arrive from %s: %s", target, row.Fixture, key))
					}
				}
			}
		}
	}
	return problems, skipped
}

func rowsOf(pairs ...string) map[string]coverageRow {
	rows := map[string]coverageRow{}
	for i := 0; i+1 < len(pairs); i += 2 {
		rows[pairs[i]] = coverageRow{Target: coverageTargets{pairs[i+1]}, Reason: "because"}
	}
	return rows
}

func TestXccdfCoverage_EveryPathAllowlisted(t *testing.T) {
	paths := walkXccdfSchemas(t)
	t.Logf("%d schema paths; first ten: %s", len(paths), strings.Join(paths[:10], ", "))

	// Paths the specification places in each schema, as a check on the walker
	// itself: an attribute three elements deep, an anyAttribute, a 1.2-only
	// element (dc-status) and a 1.1.4-only imported element (cdfp).
	for _, p := range []string{
		"Rule/check/check-content-ref/@href", "Rule/ident/@*",
		"Benchmark/Profile/select/@idref", "Rule/dc-status", "Benchmark/Platform-Specification",
	} {
		require.Contains(t, paths, p)
	}

	problems := coverageProblems(paths, loadCoverageAllowlist(t))
	require.Empty(t, problems, "xccdf-coverage.json disagrees with the schemas:\n%s", strings.Join(problems, "\n"))
}

func TestXccdfCoverage_WalkerOutputMatchesSharedDigest(t *testing.T) {
	paths := walkXccdfSchemas(t)
	pinned := loadCoverageAllowlist(t).SchemaPaths
	require.Equal(t, pinned.Count, len(paths), "the walker's path count changed; update schemaPaths in xccdf-coverage.json once both languages agree")
	require.Equal(t, pinned.SHA256, schemaPathsDigest(paths), "the walker's path list changed; update schemaPaths in xccdf-coverage.json once both languages agree")
}

func TestXccdfCoverage_UnlistedPathIsNamed(t *testing.T) {
	problems := coverageProblems([]string{"A/b", "A/c"}, coverageAllowlist{Paths: rowsOf("A/b", "skip")})
	require.Equal(t, []string{"schema path not in the allowlist: A/c"}, problems)
}

func TestXccdfCoverage_AllowlistPathNoSchemaDefinesIsNamed(t *testing.T) {
	problems := coverageProblems([]string{"A/b"}, coverageAllowlist{Paths: rowsOf("A/b", "skip", "A/zzz", "skip", "A/q/**", "skip")})
	require.Equal(t, []string{
		"allowlist subtree defined by no schema: A/q/**",
		"allowlist path defined by no schema: A/zzz",
	}, problems)
}

// An exact row inside a subtree row would fall to the subtree silently if
// deleted, so the pair is refused: split the subtree instead.
func TestXccdfCoverage_ExactRowUnderSubtreeIsNamed(t *testing.T) {
	walked := []string{"A/b", "A/b/c", "A/b/d"}
	allow := coverageAllowlist{Paths: rowsOf("A/b", "skip", "A/b/**", "skip", "A/b/c", "tags.x")}
	require.Equal(t, []string{"exact row shadowed by subtree row A/b/**: A/b/c"}, coverageProblems(walked, allow))
}

// A subtree row covers the paths below its root, never the root itself, so
// deleting the root's own row is always caught.
func TestXccdfCoverage_SubtreeRowCoversDescendantsOnly(t *testing.T) {
	walked := []string{"A/b", "A/b/c", "A/b/c/@d", "A/bx"}
	problems := coverageProblems(walked, coverageAllowlist{Paths: rowsOf("A/b/**", "skip")})
	require.Equal(t, []string{
		"schema path not in the allowlist: A/b",
		"schema path not in the allowlist: A/bx",
	}, problems)
}

func TestXccdfCoverage_SkipRowWithoutReasonFails(t *testing.T) {
	allow := coverageAllowlist{Paths: map[string]coverageRow{"A/b": {Target: coverageTargets{"skip"}}}}
	problems := coverageProblems([]string{"A/b"}, allow)
	require.Equal(t, []string{"skip row without a reason: A/b"}, problems)
}

func TestXccdfCoverage_TargetFormIsChecked(t *testing.T) {
	allow := coverageAllowlist{Paths: map[string]coverageRow{
		"A/b": {Target: coverageTargets{"tag.cce"}},
		"A/c": {Target: coverageTargets{"skip", "tags.cce"}, Reason: "because"},
		"A/d": {},
	}}
	problems := coverageProblems([]string{"A/b", "A/c", "A/d"}, allow)
	require.Equal(t, []string{
		"row with an unknown target form: A/b -> tag.cce",
		"skip combined with another target: A/c",
		"row without a target: A/d",
	}, problems)
}

func TestXccdfCoverage_VendorRowsExtendSchemaPaths(t *testing.T) {
	walked := []string{"Rule/description", "Rule/ident"}
	allow := coverageAllowlist{
		Paths: rowsOf("Rule/description", "descriptions.default", "Rule/ident", "tags.cci"),
		Vendor: rowsOf(
			"Rule/description/FalsePositives", "skip",
			"Rule/ident[@system=cci]", "tags.cci",
			"Rule/descriptions/FalseNegatives", "skip",
			"Rule/identifier[@system=cce]", "skip",
			"Rule/ident", "tags.cci",
		),
	}
	require.Equal(t, []string{
		"vendor path has no schema-defined ancestor: Rule/descriptions/FalseNegatives",
		"vendor path is schema-defined and belongs in paths: Rule/ident",
		"vendor selector on a path no schema defines: Rule/identifier[@system=cce]",
	}, coverageProblems(walked, allow))
}

func TestXccdfCoverage_MappedFieldsArrive(t *testing.T) {
	baselines := map[string]*hdf.HDFBaseline{}
	load := func(fixture string) (*hdf.HDFBaseline, error) {
		if b, ok := baselines[fixture]; ok {
			return b, nil
		}
		data, err := os.ReadFile(filepath.Join(fixtureDir(), fixture))
		if err != nil {
			return nil, err
		}
		b, err := ConvertXccdfBenchmarkToHDF(data, converterVersion)
		if err != nil {
			return nil, err
		}
		baselines[fixture] = b
		return b, nil
	}
	problems, skipped := arrivalProblems(loadCoverageAllowlist(t), load)
	t.Logf("%d rows skipped (fixture: none):\n%s", len(skipped), strings.Join(skipped, "\n"))
	require.Empty(t, problems, "mapped fields that do not arrive:\n%s", strings.Join(problems, "\n"))
}

func TestXccdfCoverage_UnfilledTargetIsNamed(t *testing.T) {
	filled := &hdf.HDFBaseline{Requirements: []hdf.BaselineRequirement{{Tags: map[string]any{"cci": []string{"CCI-000001"}}}}}
	load := func(fixture string) (*hdf.HDFBaseline, error) {
		if fixture != "x.xml" {
			return nil, fmt.Errorf("no fixture %s", fixture)
		}
		return filled, nil
	}
	allow := coverageAllowlist{
		Paths: map[string]coverageRow{
			"A": {Target: coverageTargets{"tags.cci"}, Fixture: "x.xml"},
			"B": {Target: coverageTargets{"tags.cce"}, Fixture: "x.xml"},
			"C": {Target: coverageTargets{"skip"}, Reason: "because"},
			"D": {Target: coverageTargets{"tags.cci"}},
			"E": {Target: coverageTargets{"tags.cci"}, Fixture: "none: no fixture carries it"},
			"F": {Target: coverageTargets{"tags.cci"}, Fixture: "none:"},
			"G": {Target: coverageTargets{"tags.cci"}, Fixture: "missing.xml"},
			"H": {Target: coverageTargets{"skip"}, Reason: "because", Fixture: "x.xml"},
		},
	}
	problems, skipped := arrivalProblems(allow, load)
	require.Equal(t, []string{
		"target tags.cce does not arrive from x.xml: B",
		"mapped row without a fixture: D",
		"fixture: none without a reason: F",
		"fixture missing.xml for G: no fixture missing.xml",
		"skip row names a fixture: H",
	}, problems)
	require.Equal(t, []string{"E: no fixture carries it"}, skipped)
}

// Every target form the allowlist admits has an arrival rule, and each rule
// is false on an empty Baseline and true on one that carries the value.
func TestXccdfCoverage_TargetArrivesCoversEveryTargetKind(t *testing.T) {
	title := "t"
	severity := hdf.SeverityHigh
	full := &hdf.HDFBaseline{
		Name: "n", Title: &title, Version: &title, Summary: &title,
		Groups: []hdf.RequirementGroup{{ID: "g", Title: &title, Requirements: []string{"r"}}},
		Requirements: []hdf.BaselineRequirement{{
			ID: "r", Title: &title, Impact: 0.7, Severity: &severity,
			Descriptions: []hdf.Description{{Label: "check", Data: "c"}},
			Refs:         []hdf.Reference{{URL: &title}},
			Tags:         map[string]any{"cci": []string{"CCI-000001"}, "rid": "SV-1", "documentable": false, "empty": "", "none": []string{}},
		}},
		Extensions: &hdf.Extensions{Passthrough: map[string]any{"releaseInfo": "Release: 9", "blank": ""}},
	}
	empty := &hdf.HDFBaseline{}
	// One requirement and one group with every field blank: present, not arrived.
	blank := &hdf.HDFBaseline{
		Groups:       []hdf.RequirementGroup{{}},
		Requirements: []hdf.BaselineRequirement{{Descriptions: []hdf.Description{{Label: "check", Data: ""}}, Tags: map[string]any{"cci": []string{}}}},
		Extensions:   &hdf.Extensions{Passthrough: map[string]any{"releaseInfo": ""}},
	}
	for _, target := range []string{
		"document.name", "document.title", "document.version", "document.summary",
		"requirements", "groups", "groups.id", "groups.title",
		"requirement.id", "requirement.title", "requirement.impact", "requirement.severity",
		"tags.cci", "tags.rid", "tags.documentable", "descriptions.check", "refs", "passthrough.releaseInfo",
	} {
		require.True(t, coverageTargetForm.MatchString(target), target)
		require.True(t, targetArrives(full, target), "%s on a full Baseline", target)
		require.False(t, targetArrives(empty, target), "%s on an empty Baseline", target)
		if target != "requirements" && target != "groups" {
			require.False(t, targetArrives(blank, target), "%s on a blank Baseline", target)
		}
	}
	for _, target := range []string{"tags.empty", "tags.none", "passthrough.blank", "descriptions.fix", "groups.weight", "document.id", "requirement.weight", "tag.cci"} {
		require.False(t, targetArrives(full, target), target)
	}
}

func TestXccdfCoverage_TargetAcceptsStringOrList(t *testing.T) {
	allow, err := decodeCoverageAllowlist([]byte(`{"paths":{"A":{"target":"tags.x"},"B":{"target":["requirement.id","tags.rid"]}},"vendor":{}}`))
	require.NoError(t, err)
	require.Equal(t, coverageTargets{"tags.x"}, allow.Paths["A"].Target)
	require.Equal(t, coverageTargets{"requirement.id", "tags.rid"}, allow.Paths["B"].Target)
	_, err = decodeCoverageAllowlist([]byte(`{"paths":{"A":{"target":7}},"vendor":{}}`))
	require.ErrorContains(t, err, "target")
	_, err = decodeCoverageAllowlist([]byte(`{"paths":{"A":{"target":"skip","why":"x"}},"vendor":{}}`))
	require.ErrorContains(t, err, "why")
}
