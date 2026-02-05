package legacyhdf

import (
	"time"

	hdf "github.com/mitre/hdf-schema"
)

// normalizeStatus converts v1.0 status values to v2.0 ResultStatus.
// Converts snake_case to camelCase and maps to enum values.
func normalizeStatus(status string) hdf.ResultStatus {
	statusMap := map[string]hdf.ResultStatus{
		"passed":         hdf.Passed,
		"failed":         hdf.Failed,
		"error":          hdf.Error,
		"not_applicable": hdf.NotApplicable,
		"not_reviewed":   hdf.NotReviewed,
		"skipped":        hdf.NotReviewed, // v1.0 skipped → v2.0 notReviewed
	}
	if mapped, ok := statusMap[status]; ok {
		return mapped
	}
	// Default to notReviewed for unknown statuses
	return hdf.NotReviewed
}

// parseTime parses a v1.0 timestamp string to time.Time.
func parseTime(ts string) time.Time {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t
	}
	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	// Return zero time if parsing fails
	return time.Time{}
}

// convertResult converts a v1.0 result to v2.0 RequirementResult.
func convertResult(v1 V1Result) hdf.RequirementResult {
	status := normalizeStatus(v1.Status)

	v2 := hdf.RequirementResult{
		Status:    status,
		Backtrace: v1.Backtrace,
	}

	// CodeDesc is required in v2, default to empty string
	if v1.CodeDesc != nil {
		v2.CodeDesc = *v1.CodeDesc
	}

	// StartTime is required in v2
	if v1.StartTime != nil {
		v2.StartTime = parseTime(*v1.StartTime)
	}

	if v1.RunTime != nil {
		v2.RunTime = v1.RunTime
	}
	if v1.Message != nil {
		v2.Message = v1.Message
	}
	if v1.Exception != nil {
		v2.Exception = v1.Exception
	}
	if v1.ResourceClass != nil {
		v2.Resource = v1.ResourceClass
	}
	if v1.ResourceID != nil {
		v2.ResourceID = v1.ResourceID
	}

	return v2
}

// convertControl converts a v1.0 control to v2.0 EvaluatedRequirement.
func convertControl(v1 V1Control) hdf.EvaluatedRequirement {
	v2 := hdf.EvaluatedRequirement{
		ID:     v1.ID,
		Impact: v1.Impact,
		Tags:   v1.Tags,
	}

	if v1.Title != nil {
		v2.Title = v1.Title
	}
	if v1.Code != nil {
		v2.Code = v1.Code
	}

	// Convert descriptions
	if v1.Descriptions != nil {
		v2.Descriptions = make([]hdf.Description, len(v1.Descriptions))
		for i, d := range v1.Descriptions {
			v2.Descriptions[i] = hdf.Description{
				Label: d.Label,
				Data:  d.Data,
			}
		}
	}

	// Convert source location
	if v1.SourceLocation != nil {
		srcLoc := hdf.SourceLocation{
			Ref: v1.SourceLocation.Ref,
		}
		if v1.SourceLocation.Line != nil {
			line := float64(*v1.SourceLocation.Line)
			srcLoc.Line = &line
		}
		v2.SourceLocation = &srcLoc
	}

	// Transform status to effectiveStatus with normalization
	if v1.Status != nil {
		status := normalizeStatus(*v1.Status)
		v2.EffectiveStatus = &status
	}

	// Transform results array
	if v1.Results != nil {
		v2.Results = make([]hdf.RequirementResult, len(v1.Results))
		for i, r := range v1.Results {
			v2.Results[i] = convertResult(r)
		}
	}

	return v2
}

// convertGroup converts a v1.0 group to v2.0 RequirementGroup.
// Renames controls array to requirements.
func convertGroup(v1 V1Group) hdf.RequirementGroup {
	return hdf.RequirementGroup{
		ID:           v1.ID,
		Title:        v1.Title,
		Requirements: v1.Controls, // Rename controls to requirements
	}
}

// convertDependency converts a v1.0 dependency to v2.0 Dependency.
func convertDependency(v1 V1Dependency) hdf.Dependency {
	return hdf.Dependency{
		Name:        v1.Name,
		URL:         v1.URL,
		Path:        v1.Path,
		Git:         v1.Git,
		Branch:      v1.Branch,
		Status:      v1.Status,
		Supermarket: v1.Supermarket,
		Compliance:  v1.Compliance,
	}
}

// convertProfile converts a v1.0 profile to v2.0 EvaluatedBaseline.
func convertProfile(v1 V1Profile) hdf.EvaluatedBaseline {
	v2 := hdf.EvaluatedBaseline{
		Name:           v1.Name,
		Version:        v1.Version,
		Title:          v1.Title,
		Maintainer:     v1.Maintainer,
		Summary:        v1.Summary,
		License:        v1.License,
		Copyright:      v1.Copyright,
		CopyrightEmail: v1.CopyrightEmail,
		Status:         v1.Status,
		StatusMessage:  v1.StatusMessage,
		ParentBaseline: v1.ParentProfile,
	}

	// Transform sha256 to checksum object
	if v1.SHA256 != nil {
		v2.Checksum = hdf.Checksum{
			Algorithm: hdf.Sha256,
			Value:     *v1.SHA256,
		}
	}

	// Transform groups (controls → requirements)
	if v1.Groups != nil {
		v2.Groups = make([]hdf.RequirementGroup, len(v1.Groups))
		for i, g := range v1.Groups {
			v2.Groups[i] = convertGroup(g)
		}
	}

	// Transform controls to requirements
	if v1.Controls != nil {
		v2.Requirements = make([]hdf.EvaluatedRequirement, len(v1.Controls))
		for i, c := range v1.Controls {
			v2.Requirements[i] = convertControl(c)
		}
	}

	// Transform depends
	if v1.Depends != nil {
		v2.Depends = make([]hdf.Dependency, len(v1.Depends))
		for i, d := range v1.Depends {
			v2.Depends[i] = convertDependency(d)
		}
	}

	return v2
}

// ConvertV1ToV2 converts HDF v1.0 results to v2.0 format.
//
// Performs comprehensive transformation at all levels:
//   - Top-level: version removed, profiles → baselines, platform → targets
//   - Baselines: sha256 → checksum, controls → requirements, field renaming
//   - Requirements: snake_case → camelCase, status → effectiveStatus
//   - Results: snake_case → camelCase for all fields
func ConvertV1ToV2(v1 *HDFV1Results) *hdf.HDFResults {
	v2 := &hdf.HDFResults{
		Statistics: hdf.Statistics{
			Duration: v1.Statistics.Duration,
		},
	}

	// Convert profiles to baselines
	if v1.Profiles != nil {
		v2.Baselines = make([]hdf.EvaluatedBaseline, len(v1.Profiles))
		for i, p := range v1.Profiles {
			v2.Baselines[i] = convertProfile(p)
		}
	} else {
		v2.Baselines = []hdf.EvaluatedBaseline{}
	}

	// Transform platform to targets array
	target := hdf.Target{
		Type: hdf.Host,
		Name: v1.Platform.Name,
	}
	if v1.Platform.TargetID != nil {
		target.OSName = &v1.Platform.Name // Use platform name as OS name
		target.OSVersion = v1.Platform.Release
	}
	v2.Targets = []hdf.Target{target}

	return v2
}
