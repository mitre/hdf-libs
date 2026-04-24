// Package hdfversion provides transforms between HDF schema versions.
// The router dispatches to registered transform functions, making it
// easy to add new versions without modifying the router itself.
package hdfversion

import (
	"encoding/json"
	"fmt"
	"time"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// HDFVersionTransform converts HDF data from one schema version to another.
type HDFVersionTransform func(input []byte) ([]byte, error)

// hdfTransforms is the registry of (fromVersion, toVersion) → transform pairs.
// Adding a new schema version means registering the upgrade and downgrade
// transforms here — the router logic in TransformHDF does not change.
var hdfTransforms = map[[2]string]HDFVersionTransform{
	{"1", "2"}: upgradeV1ToV2,
	{"2", "1"}: downgradeV2ToV1,
}

// TransformHDF converts HDF data between schema versions using the registered
// transform registry. Returns the input unchanged when fromVersion == toVersion.
// Returns an error for unknown version pairs.
func TransformHDF(input []byte, fromVersion, toVersion string) ([]byte, error) {
	if fromVersion == toVersion {
		return input, nil
	}

	key := [2]string{fromVersion, toVersion}
	transform, ok := hdfTransforms[key]
	if !ok {
		return nil, fmt.Errorf("no HDF transform registered for %s → %s", fromVersion, toVersion)
	}

	return transform(input)
}

// upgradeV1ToV2 converts HDF v1.0 (legacy InSpec JSON) to HDF v2.0.
// Delegates to the existing legacyhdf converter.
func upgradeV1ToV2(input []byte) ([]byte, error) {
	if !legacyhdf.IsHDFV1(input) {
		return nil, fmt.Errorf("input is not valid HDF v1.0 format")
	}

	var v1 legacyhdf.HDFV1Results
	if err := json.Unmarshal(input, &v1); err != nil {
		return nil, fmt.Errorf("failed to parse HDF v1.0: %w", err)
	}

	v2 := legacyhdf.ConvertV1ToV2(&v1)
	return json.MarshalIndent(v2, "", "  ")
}

// downgradeV2ToV1 converts HDF v2.0 to HDF v1.0 (legacy InSpec JSON).
// This is a lossy transformation — v2 fields without v1 equivalents are dropped.
//
// Lossy fields: dataSource, generator, labels, amendments, checksum metadata,
// multiple components (only first is used), component type/labels/ipAddress,
// effectiveStatus, evidence, poams, statusOverrides.
func downgradeV2ToV1(input []byte) ([]byte, error) {
	var v2 hdf.HDFResults
	if err := json.Unmarshal(input, &v2); err != nil {
		return nil, fmt.Errorf("failed to parse HDF v2.0: %w", err)
	}

	v1 := convertV2ToV1(&v2)
	return json.MarshalIndent(v1, "", "  ")
}

// convertV2ToV1 maps HDF v2 structure back to v1 structure.
func convertV2ToV1(v2 *hdf.HDFResults) *legacyhdf.HDFV1Results {
	v1 := &legacyhdf.HDFV1Results{}

	// Map components → platform (use first component)
	if len(v2.Components) > 0 {
		t := v2.Components[0]
		v1.Platform = legacyhdf.V1Platform{
			Name: t.Name,
		}
		if t.OSVersion != nil {
			v1.Platform.Release = t.OSVersion
		}
		if t.Name != "" {
			targetID := t.Name
			v1.Platform.TargetID = &targetID
		}
	}

	// Map statistics
	if v2.Statistics != nil {
		v1.Statistics = legacyhdf.V1Statistics{
			Duration: v2.Statistics.Duration,
		}
	}

	// Map baselines → profiles
	v1.Profiles = make([]legacyhdf.V1Profile, len(v2.Baselines))
	for i, baseline := range v2.Baselines {
		v1.Profiles[i] = convertBaselineToV1Profile(baseline)
	}

	return v1
}

// convertBaselineToV1Profile maps an EvaluatedBaseline back to a V1Profile.
func convertBaselineToV1Profile(b hdf.EvaluatedBaseline) legacyhdf.V1Profile {
	p := legacyhdf.V1Profile{
		Name:    b.Name,
		Version: b.Version,
		Title:   b.Title,
	}

	if b.Maintainer != nil {
		p.Maintainer = b.Maintainer
	}
	if b.Summary != nil {
		p.Summary = b.Summary
	}
	if b.License != nil {
		p.License = b.License
	}
	if b.Copyright != nil {
		p.Copyright = b.Copyright
	}
	if b.CopyrightEmail != nil {
		p.CopyrightEmail = b.CopyrightEmail
	}

	// Map groups
	p.Groups = make([]legacyhdf.V1Group, len(b.Groups))
	for i, g := range b.Groups {
		p.Groups[i] = legacyhdf.V1Group{
			ID:       g.ID,
			Title:    g.Title,
			Controls: g.Requirements,
		}
	}

	// Map dependencies
	p.Depends = make([]legacyhdf.V1Dependency, len(b.Depends))
	for i, d := range b.Depends {
		p.Depends[i] = convertDependencyToV1(d)
	}

	// Map requirements → controls
	p.Controls = make([]legacyhdf.V1Control, len(b.Requirements))
	for i, r := range b.Requirements {
		p.Controls[i] = convertRequirementToV1Control(r)
	}

	return p
}

// convertDependencyToV1 maps a Dependency to V1Dependency.
func convertDependencyToV1(d hdf.Dependency) legacyhdf.V1Dependency {
	return legacyhdf.V1Dependency{
		Name: d.Name,
		URL:  d.URL,
		Path: d.Path,
		Git:  d.Git,
	}
}

// convertRequirementToV1Control maps an EvaluatedRequirement to a V1Control.
func convertRequirementToV1Control(r hdf.EvaluatedRequirement) legacyhdf.V1Control {
	c := legacyhdf.V1Control{
		ID:     r.ID,
		Title:  r.Title,
		Impact: r.Impact,
		Code:   r.Code,
	}

	// Extract default description as desc
	for _, d := range r.Descriptions {
		if d.Label == "default" {
			desc := d.Data
			c.Desc = &desc
			break
		}
	}

	// Map tags
	if r.Tags != nil {
		c.Tags = make(map[string]interface{}, len(r.Tags))
		for k, v := range r.Tags {
			c.Tags[k] = v
		}
	}

	// Map descriptions
	c.Descriptions = make([]legacyhdf.V1Description, len(r.Descriptions))
	for i, d := range r.Descriptions {
		c.Descriptions[i] = legacyhdf.V1Description{
			Label: d.Label,
			Data:  d.Data,
		}
	}

	// Map source location
	if r.SourceLocation != nil {
		sl := legacyhdf.V1SourceLocation{
			Ref: r.SourceLocation.Ref,
		}
		if r.SourceLocation.Line != nil {
			line := int(*r.SourceLocation.Line)
			sl.Line = &line
		}
		c.SourceLocation = &sl
	}

	// Map results
	c.Results = make([]legacyhdf.V1Result, len(r.Results))
	for i, res := range r.Results {
		c.Results[i] = convertResultToV1(res)
	}

	return c
}

// convertResultToV1 maps a RequirementResult to a V1Result.
func convertResultToV1(r hdf.RequirementResult) legacyhdf.V1Result {
	v1r := legacyhdf.V1Result{
		Status:  v1StatusString(r.Status),
		Message: r.Message,
	}

	// CodeDesc is required in v2 but was pointer in v1
	codeDesc := r.CodeDesc
	v1r.CodeDesc = &codeDesc

	if r.RunTime != nil {
		v1r.RunTime = r.RunTime
	}

	// StartTime is time.Time in v2, *string in v1
	if !r.StartTime.IsZero() {
		st := r.StartTime.Format(time.RFC3339)
		v1r.StartTime = &st
	}

	if r.Exception != nil {
		v1r.Exception = r.Exception
	}
	if len(r.Backtrace) > 0 {
		v1r.Backtrace = r.Backtrace
	}

	return v1r
}

// v1StatusString converts a v2 ResultStatus enum back to v1's snake_case string.
func v1StatusString(s hdf.ResultStatus) string {
	switch s {
	case hdf.Passed:
		return "passed"
	case hdf.Failed:
		return "failed"
	case hdf.Error:
		return "error"
	case hdf.NotApplicable:
		return "not_applicable"
	case hdf.NotReviewed:
		return "not_reviewed"
	default:
		return string(s)
	}
}

// DetectHDFVersion determines if the input is HDF v1 or v2 by checking
// structural markers. Returns "1" or "2", or an error if unrecognizable.
func DetectHDFVersion(input []byte) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal(input, &obj); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// v1 has profiles + platform
	_, hasProfiles := obj["profiles"]
	_, hasPlatform := obj["platform"]
	if hasProfiles && hasPlatform {
		return "1", nil
	}

	// v2 has baselines + components
	_, hasBaselines := obj["baselines"]
	_, hasComponents := obj["components"]
	if hasBaselines && hasComponents {
		return "2", nil
	}

	return "", fmt.Errorf("cannot determine HDF version: missing expected structural fields")
}
