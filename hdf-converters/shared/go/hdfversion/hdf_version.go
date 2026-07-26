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

// HDF schema version identifiers. The taxonomy: v1 is raw InSpec exec-json
// (not a distinct HDF schema — see NormalizeVersion); v2 is the legacy Heimdall
// schema (the profiles/platform shape the heimdall2 app loads); v3 is the
// modern hdf-libs schema (baselines/components).
//
// NOTE: the legacyhdf package still names its structs HDFV1Results/V1Control etc.
// Those "V1" names predate this taxonomy fix and represent the v2 (legacy) shape;
// renaming them is a separate follow-up. Within this file the transform function
// names and version strings use the corrected numbering (2 = legacy, 3 = modern).
const (
	// LegacyVersion is the legacy Heimdall HDF schema (profiles/platform).
	LegacyVersion = "2"
	// ModernVersion is the current hdf-libs schema (baselines/components).
	ModernVersion = "3"
)

// HDFVersionTransform converts HDF data from one schema version to another.
type HDFVersionTransform func(input []byte) ([]byte, error)

// hdfTransforms is the registry of (fromVersion, toVersion) → transform pairs.
// Adding a new schema version means registering the upgrade and downgrade
// transforms here — the router logic in TransformHDF does not change.
var hdfTransforms = map[[2]string]HDFVersionTransform{
	{LegacyVersion, ModernVersion}: upgradeV2ToV3,
	{ModernVersion, LegacyVersion}: downgradeV3ToV2,
}

// NoV1Warning is emitted when a user references HDF v1. There is no distinct
// HDF v1 schema: v1 is raw InSpec exec-json, which shares the v2 (legacy
// Heimdall) shape. Ingest raw InSpec with `--from inspec`.
const NoV1Warning = "note: there is no HDF v1 schema — v1 is raw InSpec output, which shares the v2 (legacy Heimdall) shape; using v2. To ingest raw InSpec, use --from inspec."

// NormalizeVersion canonicalizes a user-supplied HDF version token. "1" has no
// distinct schema, so it maps to v2 (legacy) and returns NoV1Warning; "2" and
// "3" (and "") pass through with no warning. Callers should apply this only when
// the format is hdf, and print the returned warning (if any) once.
func NormalizeVersion(v string) (canonical, warning string) {
	if v == "1" {
		return LegacyVersion, NoV1Warning
	}
	return v, ""
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

// upgradeV2ToV3 converts the legacy Heimdall HDF schema (v2, the InSpec
// exec-json profiles/platform shape) to modern HDF (v3). Delegates to the
// existing legacyhdf converter (whose type/function names still use the older
// "V1"/"V2" spelling — see the package NOTE above).
func upgradeV2ToV3(input []byte) ([]byte, error) {
	if !legacyhdf.IsHDFV1(input) {
		return nil, fmt.Errorf("input is not the legacy HDF (v2) shape")
	}

	var legacy legacyhdf.HDFV1Results
	if err := json.Unmarshal(input, &legacy); err != nil {
		return nil, fmt.Errorf("failed to parse legacy HDF (v2): %w", err)
	}

	modern := legacyhdf.ConvertV1ToV2(&legacy)
	return json.MarshalIndent(modern, "", "  ")
}

// downgradeV3ToV2 converts modern HDF (v3) to the legacy Heimdall schema (v2,
// the InSpec exec-json shape). This is a lossy transformation — v3 fields
// without a v2 equivalent are dropped.
//
// Lossy fields: dataSource, generator, labels, amendments, checksum metadata,
// multiple components (only first is used), component type/labels/ipAddress,
// effectiveStatus, evidence, poams, statusOverrides.
func downgradeV3ToV2(input []byte) ([]byte, error) {
	var modern hdf.HDFResults
	if err := json.Unmarshal(input, &modern); err != nil {
		return nil, fmt.Errorf("failed to parse modern HDF (v3): %w", err)
	}

	legacy := convertV3ToV2(&modern)
	return json.MarshalIndent(legacy, "", "  ")
}

// convertV3ToV2 maps the modern HDF (v3) structure back to the legacy (v2) shape.
func convertV3ToV2(v2 *hdf.HDFResults) *legacyhdf.HDFV1Results {
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
		v1.Profiles[i] = convertBaselineToV2Profile(baseline)
	}

	return v1
}

// convertBaselineToV2Profile maps an EvaluatedBaseline back to a V1Profile.
func convertBaselineToV2Profile(b hdf.EvaluatedBaseline) legacyhdf.V1Profile {
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
		p.Depends[i] = convertDependencyToV2(d)
	}

	// Map requirements → controls
	p.Controls = make([]legacyhdf.V1Control, len(b.Requirements))
	for i, r := range b.Requirements {
		p.Controls[i] = convertRequirementToV2Control(r)
	}

	return p
}

// convertDependencyToV2 maps a Dependency to V1Dependency.
func convertDependencyToV2(d hdf.Dependency) legacyhdf.V1Dependency {
	return legacyhdf.V1Dependency{
		Name: d.Name,
		URL:  d.URL,
		Path: d.Path,
		Git:  d.Git,
	}
}

// convertRequirementToV2Control maps an EvaluatedRequirement to a V1Control.
func convertRequirementToV2Control(r hdf.EvaluatedRequirement) legacyhdf.V1Control {
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
		c.Results[i] = convertResultToV2(res)
	}

	return c
}

// convertResultToV2 maps a RequirementResult to a V1Result.
func convertResultToV2(r hdf.RequirementResult) legacyhdf.V1Result {
	v1r := legacyhdf.V1Result{
		Status:  v2StatusString(r.Status),
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

// v2StatusString converts a v2 ResultStatus enum back to v1's snake_case string.
func v2StatusString(s hdf.ResultStatus) string {
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

// DetectHDFVersion determines the HDF schema version from structural markers.
// Returns the legacy Heimdall version ("2", profiles/platform) or the modern
// version ("3", baselines/components), or an error if unrecognizable.
func DetectHDFVersion(input []byte) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal(input, &obj); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Legacy Heimdall schema (v2) has profiles + platform.
	_, hasProfiles := obj["profiles"]
	_, hasPlatform := obj["platform"]
	if hasProfiles && hasPlatform {
		return LegacyVersion, nil
	}

	// Modern schema (v3) has baselines + components.
	_, hasBaselines := obj["baselines"]
	_, hasComponents := obj["components"]
	if hasBaselines && hasComponents {
		return ModernVersion, nil
	}

	return "", fmt.Errorf("cannot determine HDF version: missing expected structural fields")
}
