// Package resources exposes HDF's schemas, converter catalog, and enums to an
// agent as MCP resources. The founding constraint (ADR-0007 §9) is size: a whole
// bundled schema is 100–260 KB (~50–65k tokens), so the default agent path is a
// per-$def schema *slice* (~KB), self-contained by pulling in the transitive
// closure of the definitions it references. The whole schema is retained for
// tooling but documented as expensive and never served as a default. The
// converter catalog and enums are small and served whole.
//
// All schema access goes through hdf-validators (SchemaBytes, the single source
// of truth); the catalog is built from the importable hdf-converters registry —
// never from package cmd — so this package pulls in no cobra/console surface.
package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/mitre/hdf-libs/hdf-converters/v3/registry"
	_ "github.com/mitre/hdf-libs/hdf-converters/v3/registry/all" // populate the fingerprint registry via init()
	validators "github.com/mitre/hdf-libs/hdf-validators/go/v3"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// docTypes is the eight-document HDF ecosystem, in a stable order.
var docTypes = []string{
	"hdf-results",
	"hdf-baseline",
	"hdf-system",
	"hdf-plan",
	"hdf-amendments",
	"hdf-evidence-package",
	"hdf-comparison",
	"hdf-requirement-change-event",
}

// schemaTypeByDocType maps a resource {docType} to its validators.SchemaType.
var schemaTypeByDocType = map[string]validators.SchemaType{
	"hdf-results":                  validators.TypeResults,
	"hdf-baseline":                 validators.TypeBaseline,
	"hdf-system":                   validators.TypeSystem,
	"hdf-plan":                     validators.TypePlan,
	"hdf-amendments":               validators.TypeAmendments,
	"hdf-evidence-package":         validators.TypeEvidencePackage,
	"hdf-comparison":               validators.TypeComparison,
	"hdf-requirement-change-event": validators.TypeRequirementChangeEvent,
}

func schemaTypeFor(docType string) (validators.SchemaType, bool) {
	st, ok := schemaTypeByDocType[docType]
	return st, ok
}

// refRe matches an intra-schema definition reference. Every $ref in the bundled
// schemas ends in this form (verified), so it is a complete closure walk.
var refRe = regexp.MustCompile(`#/\$defs/([A-Za-z0-9_]+)`)

// refRewriteRe matches a $ref value and captures the referenced definition
// name, so any ref — bare `#/$defs/Name` or URL-qualified
// `<bundle-url>#/$defs/Name` — can be normalized to the bare form.
var refRewriteRe = regexp.MustCompile(`("\$ref"\s*:\s*)"[^"]*#/\$defs/([A-Za-z0-9_]+)"`)

// rewriteRefs normalizes every interior $ref in a definition to the bare
// `#/$defs/Name` form. The bundled schema addresses shared primitives with
// URL-qualified refs that resolve against each primitive bundle's $id; the slice
// flattens those bundles into a single root $defs keyed by bare name, so an
// un-rewritten URL-qualified ref would dangle. This makes the slice genuinely
// self-contained: every ref resolves within the slice's own $defs.
func rewriteRefs(raw []byte) []byte {
	return refRewriteRe.ReplaceAll(raw, []byte(`${1}"#/$$defs/${2}"`))
}

// refNames returns the distinct definition names referenced anywhere in s.
func refNames(s string) []string {
	matches := refRe.FindAllStringSubmatch(s, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// namedDefs flattens a bundled schema's definitions into a name→definition map.
// The bundled schema's top-level $defs is keyed by primitive-bundle URL, with the
// actual named types nested one level down under each bundle's own $defs; this
// lifts those out. Bundles are visited in sorted order so a name that appears in
// more than one bundle resolves deterministically (first wins).
func namedDefs(schemaBytes []byte) (map[string]json.RawMessage, error) {
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(schemaBytes, &doc); err != nil {
		return nil, fmt.Errorf("parse schema $defs: %w", err)
	}
	out := map[string]json.RawMessage{}
	bundleKeys := make([]string, 0, len(doc.Defs))
	for k := range doc.Defs {
		bundleKeys = append(bundleKeys, k)
	}
	sort.Strings(bundleKeys)
	for _, bk := range bundleKeys {
		var nested struct {
			Defs map[string]json.RawMessage `json:"$defs"`
		}
		if err := json.Unmarshal(doc.Defs[bk], &nested); err == nil && len(nested.Defs) > 0 {
			names := make([]string, 0, len(nested.Defs))
			for n := range nested.Defs {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if _, exists := out[n]; !exists {
					out[n] = nested.Defs[n]
				}
			}
			continue
		}
		// A plain named def sitting at the top level (not a URL-keyed bundle).
		if !strings.Contains(bk, "/") {
			if _, exists := out[bk]; !exists {
				out[bk] = doc.Defs[bk]
			}
		}
	}
	return out, nil
}

// defNames returns the sorted names of every definition in a schema.
func defNames(schemaBytes []byte) ([]string, error) {
	nd, err := namedDefs(schemaBytes)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nd))
	for k := range nd {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

// defClosure returns root plus every definition transitively reachable from it
// via $ref, so a slice built over the closure is self-contained.
func defClosure(nd map[string]json.RawMessage, root string) []string {
	seen := map[string]bool{}
	stack := []string{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			continue
		}
		raw, ok := nd[n]
		if !ok {
			continue
		}
		seen[n] = true
		for _, ref := range refNames(string(raw)) {
			if !seen[ref] {
				stack = append(stack, ref)
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sliceForDef builds a self-contained JSON-Schema slice for a single definition:
// the definition plus the transitive closure of the definitions it references,
// under a $defs the slice's own $ref resolves against. Returns found=false (nil
// payload) for an unknown definition — never a whole-schema fallback.
func sliceForDef(schemaBytes []byte, def string) (map[string]any, bool, error) {
	nd, err := namedDefs(schemaBytes)
	if err != nil {
		return nil, false, err
	}
	if _, ok := nd[def]; !ok {
		return nil, false, nil
	}
	closure := defClosure(nd, def)
	defsAny := make(map[string]any, len(closure))
	for _, n := range closure {
		var v any
		if err := json.Unmarshal(rewriteRefs(nd[n]), &v); err != nil {
			return nil, false, fmt.Errorf("parse definition %s: %w", n, err)
		}
		defsAny[n] = v
	}
	var meta struct {
		Schema string `json:"$schema"`
		ID     string `json:"$id"`
	}
	_ = json.Unmarshal(schemaBytes, &meta)
	dialect := meta.Schema
	if dialect == "" {
		dialect = "https://json-schema.org/draft/2020-12/schema"
	}
	payload := map[string]any{
		"$schema": dialect,
		"$ref":    "#/$defs/" + def,
		"$defs":   defsAny,
	}
	if meta.ID != "" {
		payload["$comment"] = "Single-definition slice extracted from " + meta.ID +
			"; self-contained ($refs resolve within $defs)."
	}
	return payload, true, nil
}

// examplesForDef returns only a definition's examples array (with minimal
// identity), never its constraint body. A definition that declares no examples
// returns an explicit empty array rather than falling back to the constraints.
func examplesForDef(schemaBytes []byte, def string) (map[string]any, bool, error) {
	nd, err := namedDefs(schemaBytes)
	if err != nil {
		return nil, false, err
	}
	raw, ok := nd[def]
	if !ok {
		return nil, false, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, false, fmt.Errorf("parse definition %s: %w", def, err)
	}
	examples, _ := m["examples"].([]any)
	if examples == nil {
		examples = []any{}
	}
	payload := map[string]any{
		"defName":  def,
		"examples": examples,
		"count":    len(examples),
	}
	if len(examples) == 0 {
		payload["note"] = "This definition declares no examples."
	}
	return payload, true, nil
}

// catalogEntry is one row of the converter catalog.
type catalogEntry struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Direction   string `json:"direction"`
	InputFamily string `json:"inputFamily"`
	OutputType  string `json:"outputType"`
}

// converterCatalog builds the converter catalog from the importable registry,
// sorted by id for deterministic output.
func converterCatalog() []catalogEntry {
	fps := registry.GetFingerprints()
	out := make([]catalogEntry, 0, len(fps))
	for _, fp := range fps {
		out = append(out, catalogEntry{
			ID:          fp.ID,
			Label:       fp.Label,
			Direction:   string(fp.Direction),
			InputFamily: string(fp.InputFamily),
			OutputType:  string(fp.OutputType),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// enumEntry is a single HDF enumeration served whole.
type enumEntry struct {
	Name        string   `json:"name"`
	Values      []string `json:"values"`
	Description string   `json:"description,omitempty"`
}

// collectEnums gathers every string enumeration defined across the eight
// schemas, deduped by name (first occurrence in doc-type order wins). Enum value
// order is preserved from the schema.
func collectEnums() (map[string]enumEntry, error) {
	out := map[string]enumEntry{}
	for _, dt := range docTypes {
		st, ok := schemaTypeFor(dt)
		if !ok {
			continue
		}
		schemaBytes, err := validators.SchemaBytes(st)
		if err != nil {
			return nil, fmt.Errorf("load schema %s: %w", dt, err)
		}
		nd, err := namedDefs(schemaBytes)
		if err != nil {
			return nil, err
		}
		for name, raw := range nd {
			if _, exists := out[name]; exists {
				continue
			}
			var m struct {
				Enum        []any  `json:"enum"`
				Description string `json:"description"`
			}
			if err := json.Unmarshal(raw, &m); err != nil || len(m.Enum) == 0 {
				continue
			}
			values := make([]string, 0, len(m.Enum))
			for _, v := range m.Enum {
				if s, ok := v.(string); ok {
					values = append(values, s)
				}
			}
			if len(values) == 0 {
				continue
			}
			out[name] = enumEntry{Name: name, Values: values, Description: m.Description}
		}
	}
	return out, nil
}

// serveEnum returns a single enum by name.
func serveEnum(name string) (enumEntry, bool, error) {
	idx, err := collectEnums()
	if err != nil {
		return enumEntry{}, false, err
	}
	e, ok := idx[name]
	return e, ok, nil
}

// RegisterAll installs the schema-slice, whole-schema, converter-catalog, and
// enum resources on the server.
func RegisterAll(s *sdkmcp.Server) {
	// Schema slices — the expected, cheap agent path.
	s.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		Name:        "hdf-schema-slice",
		Title:       "HDF schema definition (slice)",
		URITemplate: "hdf://schema/{docType}/{def}{?view}",
		MIMEType:    "application/json",
		Description: "A single $defs type from an HDF schema as a self-contained JSON slice — the cheap, expected way to learn one type's shape (a slice is ~KB; the whole schema is 100–260 KB). {docType} is one of: " +
			strings.Join(docTypes, ", ") + ". Append ?view=examples to get only that definition's realistic examples.",
	}, handleSchemaSlice)

	// Whole schema — retained for tooling, documented as expensive, never a default.
	s.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		Name:        "hdf-schema-whole",
		Title:       "HDF whole schema (expensive)",
		URITemplate: "hdf://schema/{docType}",
		MIMEType:    "application/json",
		Description: "EXPENSIVE — the entire bundled schema for a document type (100–260 KB, ~50–65k tokens). Retained for tooling; prefer hdf://schema/{docType}/{def} for a single type. Not an agent default.",
	}, handleWholeSchema)

	// Converter catalog — small, served whole; concrete for discovery.
	s.AddResource(&sdkmcp.Resource{
		Name:        "hdf-converter-catalog",
		Title:       "HDF converter catalog",
		URI:         "hdf://catalog/converters",
		MIMEType:    "application/json",
		Description: "The registry of source formats that convert to HDF (and HDF export targets): id, label, direction, input family, output document type.",
	}, handleCatalog)

	// Enums — small, served whole. A template gives unknown names a structured
	// not-found; concrete resources make the known enums discoverable via list.
	s.AddResourceTemplate(&sdkmcp.ResourceTemplate{
		Name:        "hdf-enum",
		Title:       "HDF enum",
		URITemplate: "hdf://enum/{name}",
		MIMEType:    "application/json",
		Description: "A single HDF enumeration served whole: its allowed values and description. E.g. hdf://enum/Result_Status.",
	}, handleEnum)
	if idx, err := collectEnums(); err == nil {
		for _, name := range sortedEnumKeys(idx) {
			s.AddResource(&sdkmcp.Resource{
				Name:        "hdf-enum-" + name,
				Title:       "HDF enum: " + name,
				URI:         "hdf://enum/" + name,
				MIMEType:    "application/json",
				Description: enumDescription(idx[name]),
			}, handleEnum)
		}
	}

	// Per-session tool-call transcript (middleware recorder + read-only resource).
	RegisterTranscript(s)
}

func handleSchemaSlice(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	uri := req.Params.URI
	u, err := url.Parse(uri)
	if err != nil {
		return nil, notFound(uri, "malformed resource URI", nil)
	}
	segs := pathSegments(u)
	if len(segs) != 2 {
		return nil, notFound(uri, "expected hdf://schema/{docType}/{def}", nil)
	}
	docType, def := segs[0], segs[1]
	st, ok := schemaTypeFor(docType)
	if !ok {
		return nil, notFound(uri, fmt.Sprintf("unknown document type %q", docType), docTypes)
	}
	whole, err := validators.SchemaBytes(st)
	if err != nil {
		return nil, fmt.Errorf("load schema %s: %w", docType, err)
	}
	if u.Query().Get("view") == "examples" {
		payload, found, err := examplesForDef(whole, def)
		if err != nil {
			return nil, err
		}
		if !found {
			names, _ := defNames(whole)
			return nil, notFound(uri, fmt.Sprintf("unknown definition %q in %s", def, docType), names)
		}
		return jsonResource(uri, payload)
	}
	payload, found, err := sliceForDef(whole, def)
	if err != nil {
		return nil, err
	}
	if !found {
		names, _ := defNames(whole)
		return nil, notFound(uri, fmt.Sprintf("unknown definition %q in %s", def, docType), names)
	}
	return jsonResource(uri, payload)
}

func handleWholeSchema(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	uri := req.Params.URI
	u, err := url.Parse(uri)
	if err != nil {
		return nil, notFound(uri, "malformed resource URI", nil)
	}
	segs := pathSegments(u)
	if len(segs) != 1 {
		return nil, notFound(uri, "expected hdf://schema/{docType}", nil)
	}
	st, ok := schemaTypeFor(segs[0])
	if !ok {
		return nil, notFound(uri, fmt.Sprintf("unknown document type %q", segs[0]), docTypes)
	}
	whole, err := validators.SchemaBytes(st)
	if err != nil {
		return nil, fmt.Errorf("load schema %s: %w", segs[0], err)
	}
	return textResource(uri, string(whole))
}

func handleCatalog(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	return jsonResource(req.Params.URI, converterCatalog())
}

func handleEnum(_ context.Context, req *sdkmcp.ReadResourceRequest) (*sdkmcp.ReadResourceResult, error) {
	uri := req.Params.URI
	u, err := url.Parse(uri)
	if err != nil {
		return nil, notFound(uri, "malformed resource URI", nil)
	}
	segs := pathSegments(u)
	if len(segs) != 1 {
		return nil, notFound(uri, "expected hdf://enum/{name}", nil)
	}
	e, found, err := serveEnum(segs[0])
	if err != nil {
		return nil, err
	}
	if !found {
		idx, _ := collectEnums()
		return nil, notFound(uri, fmt.Sprintf("unknown enum %q", segs[0]), sortedEnumKeys(idx))
	}
	return jsonResource(uri, e)
}

// notFound returns a structured JSON-RPC not-found error naming the available
// alternatives — never a fallback to a different resource.
func notFound(uri, reason string, available []string) error {
	data, _ := json.Marshal(map[string]any{
		"uri":       uri,
		"reason":    reason,
		"available": available,
	})
	return &jsonrpc.Error{
		Code:    jsonrpc.CodeInvalidParams,
		Message: reason,
		Data:    json.RawMessage(data),
	}
}

func jsonResource(uri string, payload any) (*sdkmcp.ReadResourceResult, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal resource %s: %w", uri, err)
	}
	return textResource(uri, string(b))
}

func textResource(uri, text string) (*sdkmcp.ReadResourceResult, error) {
	return &sdkmcp.ReadResourceResult{
		Contents: []*sdkmcp.ResourceContents{{
			URI:      uri,
			MIMEType: "application/json",
			Text:     text,
		}},
	}, nil
}

// pathSegments returns the non-empty path segments of a resource URI. For
// hdf://schema/hdf-amendments/Override_Type the host is "schema" and the
// segments are ["hdf-amendments", "Override_Type"].
func pathSegments(u *url.URL) []string {
	p := strings.Trim(u.Path, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func sortedEnumKeys(idx map[string]enumEntry) []string {
	out := make([]string, 0, len(idx))
	for k := range idx {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func enumDescription(e enumEntry) string {
	if e.Description != "" {
		return e.Description
	}
	return "Allowed values: " + strings.Join(e.Values, ", ")
}
