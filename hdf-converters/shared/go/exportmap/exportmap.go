// Package exportmap holds the generic, source-tool-agnostic mapping helpers
// shared by the HDF export converters (hdf-to-ecs, hdf-to-splunk, ...).
//
// The export converters deliberately operate on generically-parsed JSON
// (map[string]interface{}) rather than typed hdf structs, so their output can
// be held byte-identical with the TypeScript implementations. This package
// centralizes the generic accessors, the status roll-up, the requirement/
// document field extraction, and the canonical (key-sorted, HTML-unescaped)
// line encoder — everything common to more than one exporter. Target-specific
// event shaping (ECS field names, CIM field names, envelopes) stays in each
// converter.
package exportmap

import (
	"bytes"
	"encoding/json"
	"strings"
)

// --- generic JSON access ---

// AsMap returns v as a JSON object, or (nil,false).
func AsMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// AsSlice returns v as a JSON array, or (nil,false).
func AsSlice(v interface{}) ([]interface{}, bool) {
	s, ok := v.([]interface{})
	return s, ok
}

// GetStr returns m[key] as a string, or "" when absent/non-string/nil map.
func GetStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// SetIf sets m[key]=val only when val is non-empty.
func SetIf(m map[string]interface{}, key, val string) {
	if val != "" {
		m[key] = val
	}
}

// StringSlice coerces a string or []string-ish value into []string.
func StringSlice(v interface{}) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// --- status roll-up ---

// WorstOfResults returns the most-significant status across a requirement's
// results[] (lossless — does not consult effectiveStatus). Empty results yield
// "notReviewed".
func WorstOfResults(req map[string]interface{}) string {
	results, _ := AsSlice(req["results"])
	precedence := []string{"failed", "error", "passed", "notReviewed", "notApplicable"}
	present := map[string]bool{}
	for _, rRaw := range results {
		if r, ok := AsMap(rRaw); ok {
			present[GetStr(r, "status")] = true
		}
	}
	for _, s := range precedence {
		if present[s] {
			return s
		}
	}
	return "notReviewed"
}

// Status carries the resolved status context for one requirement.
type Status struct {
	Raw        string // worstOf(results[].status)
	Effective  string // effectiveStatus, "" when absent
	Rollup     string // Effective when set, else Raw
	Overridden bool   // statusOverrides present or effectiveStatus set
}

// StatusOf resolves the status context for a requirement.
func StatusOf(req map[string]interface{}) Status {
	raw := WorstOfResults(req)
	eff := GetStr(req, "effectiveStatus")
	_, hasEff := req["effectiveStatus"]
	overrides, _ := AsSlice(req["statusOverrides"])
	rollup := eff
	if rollup == "" {
		rollup = raw
	}
	return Status{
		Raw:        raw,
		Effective:  eff,
		Rollup:     rollup,
		Overridden: len(overrides) > 0 || hasEff,
	}
}

// --- document / requirement field extraction ---

// FirstComponent returns doc.components[0] as a map, or nil.
func FirstComponent(doc map[string]interface{}) map[string]interface{} {
	comps, ok := AsSlice(doc["components"])
	if !ok || len(comps) == 0 {
		return nil
	}
	c, _ := AsMap(comps[0])
	return c
}

// FirstResultStartTime returns results[0].startTime, or fallback.
func FirstResultStartTime(req map[string]interface{}, fallback string) string {
	results, _ := AsSlice(req["results"])
	if len(results) > 0 {
		if r, ok := AsMap(results[0]); ok {
			if st := GetStr(r, "startTime"); st != "" {
				return st
			}
		}
	}
	return fallback
}

// DefaultDescription returns the "default"-labeled description data, or "".
func DefaultDescription(req map[string]interface{}) string {
	descs, _ := AsSlice(req["descriptions"])
	for _, dRaw := range descs {
		if d, ok := AsMap(dRaw); ok && GetStr(d, "label") == "default" {
			return GetStr(d, "data")
		}
	}
	return ""
}

// FirstRefURL returns the first refs[].url, or "".
func FirstRefURL(req map[string]interface{}) string {
	refs, _ := AsSlice(req["refs"])
	for _, rRaw := range refs {
		if r, ok := AsMap(rRaw); ok {
			if url := GetStr(r, "url"); url != "" {
				return url
			}
		}
	}
	return ""
}

// EventID builds a deterministic id: component | baseline | control.
func EventID(component map[string]interface{}, baselineName, controlID string) string {
	comp := ""
	if component != nil {
		comp = GetStr(component, "componentId")
		if comp == "" {
			comp = GetStr(component, "name")
		}
	}
	return strings.Join([]string{comp, baselineName, controlID}, "|")
}

// --- lossless hdf.* block ---

// BuildHDFBlock builds the lossless hdf.* namespace shared by the export
// converters: promoted snake_case scalars plus the full requirement sub-objects
// preserved verbatim. status is the lossless results roll-up (StatusOf().Raw).
func BuildHDFBlock(req, baseline map[string]interface{}, status string, overridden bool, generator, tool map[string]interface{}, converterVersion string) map[string]interface{} {
	hdf := map[string]interface{}{
		"status":           status,
		"overridden":       overridden,
		"exporter_version": converterVersion,
	}
	SetIf(hdf, "control_id", GetStr(req, "id"))
	SetIf(hdf, "baseline", GetStr(baseline, "name"))
	if v, ok := req["effectiveStatus"]; ok {
		hdf["effective_status"] = v
	}
	if v, ok := req["effectiveImpact"]; ok {
		hdf["effective_impact"] = v
	}
	if v, ok := req["impact"]; ok {
		hdf["impact"] = v
	}
	if v, ok := req["severity"]; ok {
		hdf["severity"] = v
	}
	if v, ok := req["disposition"]; ok {
		hdf["disposition"] = v
	}
	tags, _ := AsMap(req["tags"])
	if nist := tags["nist"]; nist != nil {
		hdf["nist"] = nist
	}
	if cci := tags["cci"]; cci != nil {
		hdf["cci"] = cci
	}
	passthrough := map[string]string{
		"tags":             "tags",
		"cvss":             "cvss",
		"cwe":              "cwe",
		"epss":             "epss",
		"kev":              "kev",
		"affectedPackages": "affected_packages",
		"descriptions":     "descriptions",
		"results":          "results",
		"statusOverrides":  "status_overrides",
		"poams":            "poams",
		"code":             "code",
		"refs":             "refs",
	}
	for src, dst := range passthrough {
		if v, ok := req[src]; ok {
			hdf[dst] = v
		}
	}
	if generator != nil {
		hdf["generator"] = generator
	}
	if tool != nil {
		hdf["tool"] = tool
	}
	return hdf
}

// --- canonical line encoding ---

// EncodeLine returns v as compact JSON with HTML escaping disabled and a
// trailing newline (matching a json.Encoder), so exporters can concatenate
// per-event lines into byte-identical NDJSON with the TypeScript side. Go's
// encoding/json already sorts object keys.
func EncodeLine(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
