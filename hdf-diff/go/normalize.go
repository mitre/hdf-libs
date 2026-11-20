// Package diff provides InSpec exec-json (legacy HDF v1) to HDF normalization.
//
// Legacy format uses profiles[].controls[] with snake_case fields.
// Current HDF format uses baselines[].requirements[] with camelCase fields.
package diff

import (
	"encoding/json"
	"fmt"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// IsV1Format detects whether a JSON document is InSpec exec-json (legacy HDF v1) format.
// Legacy format has "profiles" at top level; current HDF has "baselines".
func IsV1Format(data map[string]any) bool {
	_, hasProfiles := data["profiles"]
	_, hasBaselines := data["baselines"]

	if !hasProfiles {
		return false
	}

	// Check that profiles is actually an array
	if _, ok := data["profiles"].([]any); !ok {
		return false
	}

	return !hasBaselines
}

// ToV2 converts an InSpec exec-json (legacy HDF v1) document to an HDFResults struct.
// If the input is already current HDF format, parses directly. If legacy,
// converts profiles→baselines, controls→requirements, snake_case→camelCase.
// The returned warnings slice contains messages for skipped profiles/controls
// during legacy conversion. For current-format passthrough, warnings is nil.
func ToV2(data []byte) (hdf.HDFResults, []string, error) {
	// First, parse into a generic map to detect format
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return hdf.HDFResults{}, nil, err
	}

	if !IsV1Format(raw) {
		// Current HDF format: parse directly into typed struct
		result, err := hdf.UnmarshalHDFResults(data)
		return result, nil, err
	}

	// Legacy format: convert to current HDF structure
	return convertV1ToV2(raw)
}

func convertV1ToV2(raw map[string]any) (hdf.HDFResults, []string, error) {
	result := hdf.HDFResults{}
	var warnings []string

	// Convert profiles -> baselines
	profiles, _ := raw["profiles"].([]any)
	baselines := make([]hdf.EvaluatedBaseline, 0, len(profiles))
	for i, p := range profiles {
		profileMap, ok := p.(map[string]any)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("skipped profile at index %d: not a JSON object", i))
			continue
		}
		baseline, profileWarnings := normalizeProfile(profileMap)
		warnings = append(warnings, profileWarnings...)
		baselines = append(baselines, baseline)
	}
	result.Baselines = baselines

	// Convert statistics
	if stats, ok := raw["statistics"].(map[string]any); ok {
		s := normalizeStatistics(stats)
		result.Statistics = &s
	}

	// Preserve timestamp
	if ts, ok := raw["timestamp"].(string); ok && ts != "" {
		parsed := hdfutil.ParseTimestamp(ts)
		if !parsed.IsZero() {
			result.Timestamp = &parsed
		}
	}

	return result, warnings, nil
}

func normalizeProfile(profile map[string]any) (hdf.EvaluatedBaseline, []string) {
	baseline := hdf.EvaluatedBaseline{}
	var warnings []string

	baseline.Name = getString(profile, "name")

	if title, ok := profile["title"].(string); ok {
		baseline.Title = &title
	}
	if version, ok := profile["version"].(string); ok {
		baseline.Version = &version
	}

	// sha256 -> integrity
	if sha, ok := profile["sha256"].(string); ok && sha != "" {
		alg := hdf.Sha256
		baseline.Integrity = &hdf.Integrity{
			Algorithm: &alg,
			Checksum:  &sha,
		}
	}

	// Groups
	baseline.Groups = normalizeGroups(profile)

	// Supports
	baseline.Supports = normalizeSupports(profile)

	// Inputs: legacy "attributes" are unstructured maps that don't conform to
	// the typed Input schema. Store in extensions.passthrough to preserve the
	// data — `extensions` itself is closed to undeclared keys.
	if attrs := normalizeInputs(profile); len(attrs) > 0 {
		if baseline.Extensions == nil {
			baseline.Extensions = &hdf.Extensions{}
		}
		if baseline.Extensions.Passthrough == nil {
			baseline.Extensions.Passthrough = make(map[string]interface{})
		}
		baseline.Extensions.Passthrough["legacyAttributes"] = attrs
	}

	// Controls -> Requirements
	controls, _ := profile["controls"].([]any)
	reqs := make([]hdf.EvaluatedRequirement, 0, len(controls))
	for i, c := range controls {
		controlMap, ok := c.(map[string]any)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("profile %q: skipped control at index %d: not a JSON object", baseline.Name, i))
			continue
		}
		reqs = append(reqs, normalizeControl(controlMap))
	}
	baseline.Requirements = reqs

	return baseline, warnings
}

func normalizeControl(control map[string]any) hdf.EvaluatedRequirement {
	req := hdf.EvaluatedRequirement{}

	req.ID = getString(control, "id")

	if title, ok := control["title"].(string); ok {
		req.Title = &title
	}

	req.Descriptions = normalizeDescriptions(control)

	req.Impact = getFloat(control, "impact")

	// Tags
	if tags, ok := control["tags"].(map[string]any); ok {
		req.Tags = tags
	} else {
		req.Tags = map[string]any{}
	}

	// Refs
	req.Refs = normalizeRefs(control)

	// Code
	if code, ok := control["code"].(string); ok {
		req.Code = &code
	}

	// source_location or sourceLocation
	req.SourceLocation = normalizeSourceLocation(control)

	// Results
	results, _ := control["results"].([]any)
	reqResults := make([]hdf.RequirementResult, 0, len(results))
	for _, r := range results {
		resultMap, ok := r.(map[string]any)
		if !ok {
			continue
		}
		reqResults = append(reqResults, normalizeResult(resultMap))
	}
	req.Results = reqResults

	return req
}

// A default-labelled description is schema-required (minItems 1 plus a contains
// constraint), and `descriptions` is one of the fields the differ tracks — so
// dropping the legacy descriptions[] array made check and fix text changes
// invisible to it, not merely absent from the output.
func normalizeDescriptions(control map[string]any) []hdf.Description {
	legacy := []hdf.Description{}
	hasDefault := false
	raws, _ := control["descriptions"].([]any)
	for _, raw := range raws {
		dMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		label, ok := dMap["label"].(string)
		if !ok || label == "" {
			continue
		}
		if label == "default" {
			hasDefault = true
		}
		data, _ := dMap["data"].(string)
		legacy = append(legacy, hdf.Description{Label: label, Data: data})
	}

	// A legacy `default` entry is the source's own prose and wins over `desc`;
	// overwriting it from `desc` dropped that prose whenever the two differed.
	// Matches ensureDefaultDescription, which the converter uses.
	if hasDefault {
		return legacy
	}
	desc, _ := control["desc"].(string)
	return append([]hdf.Description{{Label: "default", Data: desc}}, legacy...)
}

func normalizeResult(result map[string]any) hdf.RequirementResult {
	r := hdf.RequirementResult{}

	// Status mapping: "skipped" -> "notReviewed"
	status := normalizeResultStatus(getString(result, "status"))
	r.Status = hdf.ResultStatus(status)

	// code_desc or codeDesc
	r.CodeDesc = getStringFallback(result, "code_desc", "codeDesc")

	// start_time or startTime -> parsed time
	rawStartTime := getStringFallback(result, "start_time", "startTime")
	if rawStartTime != "" {
		r.StartTime = hdfutil.ParseTimestamp(rawStartTime)
	}
	// If empty or missing, StartTime stays as zero value

	// run_time or runTime (optional)
	if rt, ok := getFloatOptional(result, "run_time"); ok {
		r.RunTime = &rt
	} else if rt, ok := getFloatOptional(result, "runTime"); ok {
		r.RunTime = &rt
	}

	// message (optional)
	if msg, ok := result["message"].(string); ok {
		r.Message = &msg
	}

	return r
}

// normalizeResultStatus maps InSpec status values to HDF ResultStatus values.
func normalizeResultStatus(status string) string {
	switch status {
	case "skipped":
		return "notReviewed"
	default:
		return status
	}
}

// Nil when the control carries no source location: emitting an empty object
// where TypeScript omits the key is the same shape divergence as the rest of
// this file, and the declared SourceLocation is a closed {ref, line}.
func normalizeSourceLocation(control map[string]any) *hdf.SourceLocation {
	var loc map[string]any
	if v, ok := control["source_location"].(map[string]any); ok {
		loc = v
	} else if v, ok := control["sourceLocation"].(map[string]any); ok {
		loc = v
	}
	if loc == nil {
		return nil
	}

	sl := &hdf.SourceLocation{}
	if ref, ok := loc["ref"].(string); ok {
		sl.Ref = &ref
	}
	if line, ok := loc["line"].(float64); ok {
		sl.Line = &line
	}
	return sl
}

func normalizeStatistics(stats map[string]any) hdf.Statistics {
	s := hdf.Statistics{}
	if d, ok := stats["duration"].(float64); ok {
		s.Duration = &d
	}
	return s
}

func normalizeGroups(profile map[string]any) []hdf.RequirementGroup {
	groups, ok := profile["groups"].([]any)
	if !ok {
		return []hdf.RequirementGroup{}
	}
	result := make([]hdf.RequirementGroup, 0, len(groups))
	for _, g := range groups {
		if gMap, ok := g.(map[string]any); ok {
			// A legacy group names its members `controls`; the declared field is
			// `requirements`. Leaving it unset both lost the membership list and
			// marshalled as null, which the schema rejects.
			members := []string{}
			if controls, ok := gMap["controls"].([]any); ok {
				for _, c := range controls {
					if id, ok := c.(string); ok {
						members = append(members, id)
					}
				}
			}
			rg := hdf.RequirementGroup{
				ID:           getString(gMap, "id"),
				Requirements: members,
			}
			if title, ok := gMap["title"].(string); ok {
				rg.Title = &title
			}
			result = append(result, rg)
		}
	}
	return result
}

func normalizeSupports(profile map[string]any) []hdf.SupportedPlatform {
	supports, ok := profile["supports"].([]any)
	if !ok {
		return []hdf.SupportedPlatform{}
	}
	result := make([]hdf.SupportedPlatform, 0, len(supports))
	for _, s := range supports {
		if sMap, ok := s.(map[string]any); ok {
			// InSpec writes these hyphenated; reading camelCase meant every key
			// but `platform` was silently dropped.
			sp := hdf.SupportedPlatform{}
			if p, ok := sMap["platform"].(string); ok && p != "" {
				sp.Platform = &p
			}
			if pf, ok := sMap["platform-family"].(string); ok && pf != "" {
				sp.PlatformFamily = &pf
			}
			if pn, ok := sMap["platform-name"].(string); ok && pn != "" {
				sp.PlatformName = &pn
			}
			if r, ok := sMap["release"].(string); ok && r != "" {
				sp.Release = &r
			}
			if sp.Platform == nil && sp.PlatformFamily == nil && sp.PlatformName == nil && sp.Release == nil {
				continue
			}
			result = append(result, sp)
		}
	}
	return result
}

func normalizeInputs(profile map[string]any) []map[string]any {
	attrs, ok := profile["attributes"].([]any)
	if !ok {
		return []map[string]any{}
	}
	result := make([]map[string]any, 0, len(attrs))
	for _, a := range attrs {
		if aMap, ok := a.(map[string]any); ok {
			result = append(result, aMap)
		}
	}
	return result
}

func normalizeRefs(control map[string]any) []hdf.Reference {
	refs, ok := control["refs"].([]any)
	if !ok {
		return []hdf.Reference{}
	}
	result := make([]hdf.Reference, 0, len(refs))
	for _, r := range refs {
		if ref := normalizeRef(r); ref != nil {
			result = append(result, *ref)
		}
	}
	return result
}

// A Reference with nothing in it fails the schema, which requires one of ref,
// url or uri. Real InSpec emits `{"ref": []}`, so preserving a slot for it (the
// previous behaviour) emitted an empty Reference and made the output invalid.
// Mirrors convertRef in the legacyhdf-to-hdf converter.
func normalizeRef(raw any) *hdf.Reference {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		s := v
		return &hdf.Reference{Ref: &hdf.Ref{String: &s}}
	case map[string]any:
		ref := &hdf.Reference{}
		has := false
		if r := normalizeRefValue(v["ref"]); r != nil {
			ref.Ref = r
			has = true
		}
		if u, ok := v["url"].(string); ok && u != "" {
			ref.URL = &u
			has = true
		}
		if u, ok := v["uri"].(string); ok && u != "" {
			ref.URI = &u
			has = true
		}
		if !has {
			return nil
		}
		return ref
	}
	return nil
}

// Ref is a union of a string and an array of objects; an empty array carries
// nothing, so it is absence rather than a value.
func normalizeRefValue(raw any) *hdf.Ref {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		s := v
		return &hdf.Ref{String: &s}
	case []any:
		maps := make([]map[string]any, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				maps = append(maps, m)
			}
		}
		if len(maps) == 0 {
			return nil
		}
		return &hdf.Ref{AnythingMapArray: maps}
	}
	return nil
}

// Helper functions for safe type extraction from map[string]any.

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func getStringFallback(m map[string]any, snakeKey, camelKey string) string {
	if v, ok := m[snakeKey].(string); ok {
		return v
	}
	if v, ok := m[camelKey].(string); ok {
		return v
	}
	return ""
}

func getFloat(m map[string]any, key string) float64 {
	if v, ok := m[key].(float64); ok {
		return v
	}
	return 0
}

func getFloatOptional(m map[string]any, key string) (float64, bool) {
	v, ok := m[key].(float64)
	return v, ok
}
