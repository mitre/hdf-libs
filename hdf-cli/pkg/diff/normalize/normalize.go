// Package normalize provides v1 InSpec exec-json to HDF v2 normalization.
//
// V1 format uses profiles[].controls[] with snake_case fields.
// V2 format uses baselines[].requirements[] with camelCase fields.
package normalize

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	hdf "github.com/mitre/hdf-cli/pkg/hdf"
)

// IsV1Format detects whether a JSON document is v1 InSpec exec-json format.
// V1 has "profiles" at top level; v2 has "baselines".
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

// ToV2 converts a v1 document to an HdfResults struct.
// If already v2, parses directly. If v1, converts profiles->baselines,
// controls->requirements, snake_case->camelCase.
// The returned warnings slice contains messages for skipped profiles/controls
// during v1 conversion. For v2 passthrough, warnings is nil.
func ToV2(data []byte) (hdf.HdfResults, []string, error) {
	// First, parse into a generic map to detect format
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return hdf.HdfResults{}, nil, err
	}

	if !IsV1Format(raw) {
		// V2 format: parse directly into typed struct
		result, err := hdf.UnmarshalHdfResults(data)
		return result, nil, err
	}

	// V1 format: convert to v2 structure
	return convertV1ToV2(raw)
}

func convertV1ToV2(raw map[string]any) (hdf.HdfResults, []string, error) {
	result := hdf.HdfResults{}
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
		result.Statistics = normalizeStatistics(stats)
	}

	// Preserve timestamp
	if ts, ok := raw["timestamp"].(string); ok && ts != "" {
		parsed := parseTimestamp(ts)
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

	// sha256 -> checksum
	if sha, ok := profile["sha256"].(string); ok && sha != "" {
		baseline.Checksum = hdf.Checksum{
			Algorithm: hdf.Sha256,
			Value:     sha,
		}
	}

	// Groups
	baseline.Groups = normalizeGroups(profile)

	// Supports
	baseline.Supports = normalizeSupports(profile)

	// Inputs (v1 "attributes" → v2 "inputs")
	baseline.Inputs = normalizeInputs(profile)

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

	// desc -> descriptions array
	if desc, ok := control["desc"].(string); ok && desc != "" {
		req.Descriptions = []hdf.Description{
			{Label: "default", Data: desc},
		}
	} else {
		req.Descriptions = []hdf.Description{}
	}

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

func normalizeResult(result map[string]any) hdf.RequirementResult {
	r := hdf.RequirementResult{}

	// Status mapping: "skipped" -> "notReviewed"
	status := normalizeResultStatus(getString(result, "status"))
	statusEnum := hdf.ResultStatus(status)
	r.Status = &statusEnum

	// code_desc or codeDesc
	r.CodeDesc = getStringFallback(result, "code_desc", "codeDesc")

	// start_time or startTime -> parsed time
	rawStartTime := getStringFallback(result, "start_time", "startTime")
	if rawStartTime != "" {
		r.StartTime = parseTimestamp(rawStartTime)
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

// normalizeResultStatus maps InSpec v1 status values to HDF v2 ResultStatus values.
func normalizeResultStatus(status string) string {
	switch status {
	case "skipped":
		return "notReviewed"
	default:
		return status
	}
}

// parseTimestamp normalizes a timestamp string to a time.Time.
// Supports ISO 8601 (with 'T') and InSpec format "YYYY-MM-DD HH:MM:SS +HHMM".
// Returns zero time if unparseable.
func parseTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	// Already ISO 8601 with T
	if strings.Contains(ts, "T") {
		t, err := time.Parse(time.RFC3339, ts)
		if err == nil {
			return t
		}
		// Try RFC3339Nano
		t, err = time.Parse(time.RFC3339Nano, ts)
		if err == nil {
			return t
		}
	}

	// Try InSpec format: "2017-09-22 14:12:15 -0400"
	t, err := time.Parse("2006-01-02 15:04:05 -0700", ts)
	if err == nil {
		return t
	}

	// Try other common formats
	t, err = time.Parse("2006-01-02 15:04:05", ts)
	if err == nil {
		return t
	}

	// Unparseable: return zero time
	return time.Time{}
}

func normalizeSourceLocation(control map[string]any) hdf.SourceLocation {
	sl := hdf.SourceLocation{}

	// Try snake_case first, then camelCase
	var loc map[string]any
	if v, ok := control["source_location"].(map[string]any); ok {
		loc = v
	} else if v, ok := control["sourceLocation"].(map[string]any); ok {
		loc = v
	}

	if loc != nil {
		if ref, ok := loc["ref"].(string); ok {
			sl.Ref = &ref
		}
		if line, ok := loc["line"].(float64); ok {
			sl.Line = &line
		}
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
			rg := hdf.RequirementGroup{
				ID: getString(gMap, "id"),
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
			sp := hdf.SupportedPlatform{}
			if p, ok := sMap["platform"].(string); ok {
				sp.Platform = &p
			}
			if pn, ok := sMap["platformName"].(string); ok {
				sp.PlatformName = &pn
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
		ref := hdf.Reference{}
		switch v := r.(type) {
		case string:
			// Plain string ref: wrap in Ref.String
			ref.Ref = &hdf.Ref{String: &v}
		case map[string]any:
			// Object ref: extract "ref", "url", "uri" fields
			if refStr, ok := v["ref"].(string); ok {
				ref.Ref = &hdf.Ref{String: &refStr}
			}
			if urlStr, ok := v["url"].(string); ok {
				ref.URL = &urlStr
			}
			if uriStr, ok := v["uri"].(string); ok {
				ref.URI = &uriStr
			}
		default:
			// Unknown format: add empty Reference to preserve count
		}
		result = append(result, ref)
	}
	return result
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
