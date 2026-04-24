package splunk

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// SplunkMeta contains the metadata for each Splunk event.
type SplunkMeta struct {
	GUID            string `json:"guid"`
	Subtype         string `json:"subtype"`
	HDFSplunkSchema string `json:"hdf_splunk_schema"`
	Filetype        string `json:"filetype"`
	Filename        string `json:"filename"`
	ProfileSHA256   string `json:"profile_sha256"`
	Status          string `json:"status"`
	IsBaseline      *bool  `json:"is_baseline,omitempty"`
	IsWaived        *bool  `json:"is_waived,omitempty"`
	OverlayDepth    *int   `json:"overlay_depth,omitempty"`
}

// SplunkEvent is a wrapper to extract the meta field from any event.
type SplunkEvent struct {
	Meta json.RawMessage `json:"meta"`
}

// SplunkHeader represents a header event.
type SplunkHeader struct {
	Meta       SplunkMeta             `json:"meta"`
	Profiles   []json.RawMessage      `json:"profiles"`
	Platform   SplunkPlatform         `json:"platform"`
	Statistics map[string]interface{} `json:"statistics"`
	Version    string                 `json:"version"`
}

// SplunkPlatform holds platform identification from the header.
type SplunkPlatform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
}

// SplunkProfile represents a profile event.
type SplunkProfile struct {
	Meta       SplunkMeta        `json:"meta"`
	Name       string            `json:"name"`
	Title      string            `json:"title"`
	SHA256     string            `json:"sha256"`
	Version    string            `json:"version"`
	Summary    string            `json:"summary"`
	Copyright  string            `json:"copyright"`
	Maintainer string            `json:"maintainer"`
	License    string            `json:"license"`
	Supports   []json.RawMessage `json:"supports"`
	Groups     []SplunkGroup     `json:"groups"`
	Attributes []json.RawMessage `json:"attributes"`
	Controls   []json.RawMessage `json:"controls"`
}

// SplunkGroup represents a group of controls within a profile.
type SplunkGroup struct {
	ID       string   `json:"id"`
	Controls []string `json:"controls"`
}

// SplunkControl represents a control event.
type SplunkControl struct {
	Meta           SplunkMeta             `json:"meta"`
	ID             string                 `json:"id"`
	Title          string                 `json:"title"`
	Desc           string                 `json:"desc"`
	Descriptions   map[string]string      `json:"descriptions"`
	Impact         float64                `json:"impact"`
	Code           string                 `json:"code"`
	Tags           map[string]interface{} `json:"tags"`
	Results        []SplunkResult         `json:"results"`
	Refs           []interface{}          `json:"refs"`
	SourceLocation *SplunkSourceLocation  `json:"source_location,omitempty"`
}

// SplunkResult represents a single test result within a control.
type SplunkResult struct {
	Status      string   `json:"status"`
	CodeDesc    string   `json:"code_desc"`
	Message     string   `json:"message,omitempty"`
	StartTime   string   `json:"start_time"`
	RunTime     *float64 `json:"run_time,omitempty"`
	SkipMessage string   `json:"skip_message,omitempty"`
	Exception   string   `json:"exception,omitempty"`
	Backtrace   []string `json:"backtrace,omitempty"`
	Resource    string   `json:"resource,omitempty"`
}

// SplunkSourceLocation describes where a control is defined in source.
type SplunkSourceLocation struct {
	Ref  string  `json:"ref"`
	Line float64 `json:"line"`
}

// ConvertSplunkToHDF reassembles Splunk events (header, profile, control)
// into HDF Results format. The input is a JSON array of Splunk events that
// were originally decomposed from HDF data for Splunk storage.
func ConvertSplunkToHDF(input []byte, converterVersion string) (*hdf.HDFResults, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("splunk: empty input")
	}
	if err := shared.ValidateJSONSize(input, "splunk", 0); err != nil {
		return nil, fmt.Errorf("splunk: %w", err)
	}

	resultsChecksum := shared.InputChecksum(input)

	var rawEvents []json.RawMessage
	if err := json.Unmarshal(input, &rawEvents); err != nil {
		return nil, fmt.Errorf("invalid Splunk JSON: %w", err)
	}
	if len(rawEvents) == 0 {
		return nil, fmt.Errorf("no Splunk events found in input")
	}

	// Classify each raw event by extracting its meta.subtype, then group by GUID.
	type classifiedEvent struct {
		meta SplunkMeta
		raw  json.RawMessage
	}
	eventsByGUID := make(map[string][]classifiedEvent)

	for i, raw := range rawEvents {
		var envelope SplunkEvent
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return nil, fmt.Errorf("event %d: failed to parse envelope: %w", i, err)
		}

		var meta SplunkMeta
		if err := json.Unmarshal(envelope.Meta, &meta); err != nil {
			return nil, fmt.Errorf("event %d: failed to parse meta: %w", i, err)
		}

		eventsByGUID[meta.GUID] = append(eventsByGUID[meta.GUID], classifiedEvent{
			meta: meta,
			raw:  raw,
		})
	}

	// Process each GUID group into baselines and targets.
	var allBaselines []hdf.EvaluatedBaseline
	var allTargets []hdf.Component
	var lastHeader *SplunkHeader
	timestamp := time.Now()

	// Sort GUIDs for deterministic output.
	guids := make([]string, 0, len(eventsByGUID))
	for guid := range eventsByGUID {
		guids = append(guids, guid)
	}
	sort.Strings(guids)

	for _, guid := range guids {
		events := eventsByGUID[guid]

		// Sub-group by subtype.
		var headerEvents, profileEvents, controlEvents []json.RawMessage
		for _, ev := range events {
			switch ev.meta.Subtype {
			case "header":
				headerEvents = append(headerEvents, ev.raw)
			case "profile":
				profileEvents = append(profileEvents, ev.raw)
			case "control":
				controlEvents = append(controlEvents, ev.raw)
			}
		}

		// Validate exactly 1 header event per GUID.
		if len(headerEvents) != 1 {
			return nil, fmt.Errorf("GUID %s: expected 1 header event, got %d", guid, len(headerEvents))
		}

		// Parse header.
		var header SplunkHeader
		if err := json.Unmarshal(headerEvents[0], &header); err != nil {
			return nil, fmt.Errorf("GUID %s: failed to parse header: %w", guid, err)
		}
		lastHeader = &header

		// Parse profiles.
		profiles := make([]SplunkProfile, 0, len(profileEvents))
		for i, raw := range profileEvents {
			var profile SplunkProfile
			if err := json.Unmarshal(raw, &profile); err != nil {
				return nil, fmt.Errorf("GUID %s: failed to parse profile %d: %w", guid, i, err)
			}
			profiles = append(profiles, profile)
		}

		// Parse controls and group by profile_sha256.
		controlsByProfile := make(map[string][]SplunkControl)
		for i, raw := range controlEvents {
			var control SplunkControl
			if err := json.Unmarshal(raw, &control); err != nil {
				return nil, fmt.Errorf("GUID %s: failed to parse control %d: %w", guid, i, err)
			}
			sha := control.Meta.ProfileSHA256
			controlsByProfile[sha] = append(controlsByProfile[sha], control)
		}

		// Convert each profile to an EvaluatedBaseline.
		for _, profile := range profiles {
			baseline := convertProfileToBaseline(profile, controlsByProfile[profile.SHA256], resultsChecksum)
			allBaselines = append(allBaselines, baseline)
		}

		// Build target from header platform info.
		target := hdf.Component{
			Name: header.Platform.Name,
			Type: hdf.Host,
		}
		if header.Platform.Release != "" {
			target.OSVersion = hdfutil.Ptr(header.Platform.Release)
		}
		allTargets = append(allTargets, target)
	}

	// Build statistics from the last header.
	var stats *hdf.Statistics
	if lastHeader != nil {
		stats = convertStatistics(lastHeader.Statistics)
	}

	hdfResult := shared.BuildHDFResults(shared.HDFResultsOptions{
		GeneratorName:    "splunk-to-hdf",
		ConverterVersion: converterVersion,
		ToolName:         "Splunk",
		Baselines:        allBaselines,
		Components:       allTargets,
		Statistics:       stats,
		Timestamp:        &timestamp,
	})

	return hdfResult, nil
}

// convertProfileToBaseline converts a SplunkProfile and its associated controls
// into an HDF EvaluatedBaseline.
func convertProfileToBaseline(
	profile SplunkProfile,
	controls []SplunkControl,
	resultsChecksum *hdf.Checksum,
) hdf.EvaluatedBaseline {
	// Convert groups.
	groups := make([]hdf.RequirementGroup, 0, len(profile.Groups))
	for _, g := range profile.Groups {
		groups = append(groups, hdf.RequirementGroup{
			ID:           g.ID,
			Requirements: g.Controls,
		})
	}

	// Convert controls to requirements.
	requirements := make([]hdf.EvaluatedRequirement, 0, len(controls))
	for _, ctrl := range controls {
		req := convertControlToRequirement(ctrl)
		requirements = append(requirements, req)
	}

	// Parse supports from raw JSON.
	supports := make([]hdf.SupportedPlatform, 0, len(profile.Supports))
	for _, raw := range profile.Supports {
		var sp hdf.SupportedPlatform
		if err := json.Unmarshal(raw, &sp); err == nil {
			supports = append(supports, sp)
		}
	}

	baseline := hdf.EvaluatedBaseline{
		Name:            profile.Name,
		Title:           hdfutil.Ptr(profile.Title),
		Version:         hdfutil.Ptr(profile.Version),
		Summary:         hdfutil.Ptr(profile.Summary),
		Maintainer:      hdfutil.Ptr(profile.Maintainer),
		Copyright:       hdfutil.Ptr(profile.Copyright),
		License:         hdfutil.Ptr(profile.License),
		Groups:          groups,
		Supports:        supports,
		Requirements:    requirements,
		ResultsChecksum: resultsChecksum,
	}

	if profile.SHA256 != "" {
		alg := hdf.Sha256
		baseline.Integrity = &hdf.Integrity{
			Algorithm: &alg,
			Checksum:  &profile.SHA256,
		}
	}

	return baseline
}

// convertControlToRequirement converts a single SplunkControl into an HDF
// EvaluatedRequirement.
func convertControlToRequirement(ctrl SplunkControl) hdf.EvaluatedRequirement {
	// Convert descriptions from map[string]string to []hdf.Description.
	descriptions := make([]hdf.Description, 0, len(ctrl.Descriptions))
	// Sort keys for deterministic output.
	descKeys := make([]string, 0, len(ctrl.Descriptions))
	for k := range ctrl.Descriptions {
		descKeys = append(descKeys, k)
	}
	sort.Strings(descKeys)
	for _, key := range descKeys {
		descriptions = append(descriptions, hdf.Description{
			Label: key,
			Data:  ctrl.Descriptions[key],
		})
	}

	// If no descriptions exist, add a default one from Desc.
	if len(descriptions) == 0 {
		descriptions = append(descriptions, hdf.Description{
			Label: "default",
			Data:  ctrl.Desc,
		})
	}

	// Convert results.
	results := make([]hdf.RequirementResult, 0, len(ctrl.Results))
	for _, r := range ctrl.Results {
		result := convertSplunkResult(r)
		results = append(results, result)
	}

	// Build source location.
	var sourceLocation *hdf.SourceLocation
	if ctrl.SourceLocation != nil {
		ref := ctrl.SourceLocation.Ref
		line := ctrl.SourceLocation.Line
		sourceLocation = &hdf.SourceLocation{
			Ref:  &ref,
			Line: &line,
		}
	}

	req := hdf.EvaluatedRequirement{
		ID:             ctrl.ID,
		Title:          hdfutil.Ptr(ctrl.Title),
		Impact:         ctrl.Impact,
		Code:           hdfutil.Ptr(ctrl.Code),
		Tags:           ctrl.Tags,
		Descriptions:   descriptions,
		Results:        results,
		SourceLocation: sourceLocation,
	}

	return req
}

// convertSplunkResult maps a SplunkResult to an HDF RequirementResult.
func convertSplunkResult(r SplunkResult) hdf.RequirementResult {
	status := mapStatus(r.Status)
	startTime := hdfutil.ParseTimestamp(r.StartTime)

	result := hdf.RequirementResult{
		Status:    status,
		CodeDesc:  r.CodeDesc,
		StartTime: startTime,
	}

	if r.Message != "" {
		result.Message = hdfutil.Ptr(r.Message)
	}
	if r.RunTime != nil {
		result.RunTime = r.RunTime
	}
	if r.SkipMessage != "" {
		result.Message = hdfutil.Ptr(r.SkipMessage)
	}
	if r.Exception != "" {
		result.Exception = hdfutil.Ptr(r.Exception)
	}
	if len(r.Backtrace) > 0 {
		result.Backtrace = r.Backtrace
	}
	if r.Resource != "" {
		result.Resource = hdfutil.Ptr(r.Resource)
	}

	return result
}

// mapStatus converts a Splunk status string to an HDF ResultStatus.
func mapStatus(s string) hdf.ResultStatus {
	switch s {
	case "passed":
		return hdf.Passed
	case "failed":
		return hdf.Failed
	case "skipped":
		return hdf.NotReviewed
	case "error":
		return hdf.Error
	default:
		return hdf.NotReviewed
	}
}

// convertStatistics extracts the duration from the Splunk header statistics
// map and returns an HDF Statistics struct.
func convertStatistics(stats map[string]interface{}) *hdf.Statistics {
	if stats == nil {
		return nil
	}

	result := &hdf.Statistics{}

	if dur, ok := stats["duration"]; ok {
		switch v := dur.(type) {
		case float64:
			result.Duration = &v
		case json.Number:
			if f, err := v.Float64(); err == nil {
				result.Duration = &f
			}
		}
	}

	return result
}
