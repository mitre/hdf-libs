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
	"fmt"
	"strconv"
	"strings"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
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
// results[] (lossless — does not consult effectiveStatus), using the canonical
// worst-wins ordering from hdf-utilities. Empty results yield "notReviewed".
func WorstOfResults(req map[string]interface{}) string {
	return hdfutil.WorstStatus(resultStatuses(req))
}

// IsFailing reports whether an HDF Result_Status is a failing verdict. Only
// "failed" fails; "error" is indeterminate (not a compliance failure) and every
// other value is non-failing. This is the single definition of "failing" shared
// by the suppression axis and the per-exporter outcome maps.
func IsFailing(status string) bool { return status == "failed" }

// Status carries the resolved status context for one requirement.
type Status struct {
	Raw        string // worstOf(results[].status) — the RAW verdict
	Rollup     string // canonical effective status (ladder: override → error → impact-0 → roll-up)
	Overridden bool   // statusOverride records present
	// Suppressed is the acceptance axis, orthogonal to the raw verdict: the raw
	// result is failing but an override drove the effective status non-failing
	// (waiver / falsePositive / attestation). A riskAdjustment / operational-
	// requirement / poam that leaves effectiveStatus failing is NOT suppressed —
	// it stays actionable, only its impact is re-scored. This is why suppression
	// is keyed on the effective STATUS, not on "any override present".
	Suppressed bool
}

// StatusOf resolves the status context for a requirement via the canonical
// effective-status ladder — the stored effectiveStatus field is never read
// (see status-determination.md; the field is an output cache).
func StatusOf(req map[string]interface{}) Status {
	raw := WorstOfResults(req)
	overrides, _ := AsSlice(req["statusOverrides"])

	// impact is schema-required; when a malformed map lacks it, do not read
	// the absence as 0 (which would force notApplicable) — skip the impact-0
	// rung instead, matching hdf-diff's wrapper.
	impact := 1.0
	if v, ok := req["impact"].(float64); ok {
		impact = v
	}

	overrideIns := overrideInputs(overrides)
	rollup := hdfutil.ComputeEffectiveStatus(hdfutil.EffectiveStatusInput{
		Impact:         impact,
		ResultStatuses: resultStatuses(req),
		Overrides:      overrideIns,
	}, time.Time{})

	// Suppression is the ACCEPTANCE axis: a governing override drove a failing
	// raw verdict non-failing. The ladder's own impact-0 rule also yields a
	// non-failing status, but that is structural Not Applicable, not an
	// acceptance decision — so suppression additionally requires a governing
	// override.
	governed := hdfutil.GoverningStatusOverride(overrideIns, time.Time{}) != nil

	return Status{
		Raw:        raw,
		Rollup:     rollup,
		Overridden: len(overrides) > 0,
		Suppressed: governed && IsFailing(raw) && !IsFailing(rollup),
	}
}

// overrideInputs maps raw statusOverride objects onto the canonical helper's
// neutral shape, parsing timestamps with the repo's canonical parser.
func overrideInputs(overrides []interface{}) []hdfutil.StatusOverrideInput {
	inputs := make([]hdfutil.StatusOverrideInput, 0, len(overrides))
	for _, oRaw := range overrides {
		o, ok := AsMap(oRaw)
		if !ok {
			continue
		}
		inputs = append(inputs, hdfutil.StatusOverrideInput{
			Status:    GetStr(o, "status"),
			AppliedAt: hdfutil.ParseTimestamp(GetStr(o, "appliedAt")),
			ExpiresAt: hdfutil.ParseTimestamp(GetStr(o, "expiresAt")),
		})
	}
	return inputs
}

// resultStatuses lists results[].status losslessly for the canonical roll-up.
func resultStatuses(req map[string]interface{}) []string {
	results, _ := AsSlice(req["results"])
	statuses := make([]string, 0, len(results))
	for _, rRaw := range results {
		if r, ok := AsMap(rRaw); ok {
			statuses = append(statuses, GetStr(r, "status"))
		}
	}
	return statuses
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
// preserved verbatim. status is the lossless results roll-up (StatusOf().Raw);
// suppressed is the acceptance axis (StatusOf().Suppressed).
func BuildHDFBlock(req, baseline map[string]interface{}, status string, overridden, suppressed bool, generator, tool map[string]interface{}, converterVersion string) map[string]interface{} {
	hdf := map[string]interface{}{
		"status":           status,
		"overridden":       overridden,
		"suppressed":       suppressed,
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

// FloatToken renders a float as a JSON number that always bears a decimal point,
// so a whole-number value serializes as `10.0` rather than the integer `10`.
// Some consumers type-check strictly (OCSF's `float_t` rejects an integer-shaped
// token); json.Number marshals verbatim, keeping this byte-identical with the
// TypeScript RawNumber. Domain is low-precision decimals (e.g. CVSS scores),
// where Go's shortest-decimal format and JS's String() agree.
func FloatToken(f float64) json.Number {
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return json.Number(s)
}

// --- shared export driver ---

// EventBuilder maps one requirement (with its baseline and doc-level context) to
// one output object. The doc-level context (docTimestamp/tool/generator/
// component) is supplied by the driver; per-exporter constants (e.g. the
// converter version) are captured by the closure the exporter passes in. This
// keeps the driver target-agnostic — a new exporter only writes a builder.
type EventBuilder func(req, baseline map[string]interface{}, docTimestamp string, tool, generator, component map[string]interface{}) map[string]interface{}

// Export is the shared entry-point driver for the HDF→SIEM exporters. It runs
// the identical prologue every exporter needs — empty guard, JSON-size
// validation, parse, baselines extraction, doc-level context — then fans out one
// output object per requirement via build and concatenates the canonical NDJSON
// lines (byte-identical with the TypeScript side via EncodeLine). converterName
// prefixes every error and drives ValidateJSONSize's limit lookup.
func Export(input []byte, converterName string, build EventBuilder) ([]byte, error) {
	doc, baselines, err := shared.RequireHDFResults(input, converterName)
	if err != nil {
		return nil, err
	}

	docTimestamp := GetStr(doc, "timestamp")
	tool, _ := AsMap(doc["tool"])
	generator, _ := AsMap(doc["generator"])
	component := FirstComponent(doc)

	var buf bytes.Buffer
	for _, bRaw := range baselines {
		baseline, ok := AsMap(bRaw)
		if !ok {
			continue
		}
		reqs, _ := AsSlice(baseline["requirements"])
		for _, rRaw := range reqs {
			req, ok := AsMap(rRaw)
			if !ok {
				continue
			}
			line, err := EncodeLine(build(req, baseline, docTimestamp, tool, generator, component))
			if err != nil {
				return nil, fmt.Errorf("%s: encode: %w", converterName, err)
			}
			buf.Write(line)
		}
	}
	return buf.Bytes(), nil
}

// FirstCVE returns the first cvss[].source that looks like a CVE id
// (case-insensitive "CVE-" prefix), or "". Shared by the exporters that key a
// vulnerability identity off the CVE (splunk, ocsf).
func FirstCVE(cvssList []interface{}) string {
	for _, c := range cvssList {
		if m, ok := AsMap(c); ok {
			src := GetStr(m, "source")
			if len(src) >= 4 && strings.EqualFold(src[:4], "CVE-") {
				return src
			}
		}
	}
	return ""
}

// EpochSeconds parses an HDF RFC3339 timestamp into integer epoch seconds via
// the canonical parser, returning (0,false) when empty/unparseable. Splunk HEC
// stamps `time` in epoch seconds.
func EpochSeconds(s string) (int64, bool) {
	t := hdfutil.ParseTimestamp(s)
	if t.IsZero() {
		return 0, false
	}
	return t.Unix(), true
}

// EpochMillis parses an HDF RFC3339 timestamp into integer epoch milliseconds
// via the canonical parser, returning (0,false) when empty/unparseable. OCSF's
// `time` is epoch millis. Integer epoch keeps Go and TypeScript byte-identical.
func EpochMillis(s string) (int64, bool) {
	t := hdfutil.ParseTimestamp(s)
	if t.IsZero() {
		return 0, false
	}
	return t.UnixMilli(), true
}
