package legacyhdf

import (
	"strconv"
	"time"

	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdfparsers "github.com/mitre/hdf-libs/hdf-parsers/go/v3"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// computeEffectiveStatus derives effectiveStatus from impact and v2 results.
// Implements InSpec enhanced outcomes precedence:
//
//	impact=0 → notApplicable
//	error > failed > passed > notApplicable > notReviewed
//
// See docs/design/status-determination.md for full specification.
func computeEffectiveStatus(impact float64, results []hdf.RequirementResult) hdf.ResultStatus {
	if impact == 0 {
		return hdf.NotApplicable
	}
	if len(results) == 0 {
		return hdf.NotReviewed
	}

	hasFailed := false
	hasPassed := false
	hasNotApplicable := false

	for _, r := range results {
		switch r.Status {
		case hdf.Error:
			return hdf.Error // fail-fast: highest precedence
		case hdf.Failed:
			hasFailed = true
		case hdf.Passed:
			hasPassed = true
		case hdf.NotApplicable:
			hasNotApplicable = true
		case hdf.NotReviewed:
			// lowest precedence
		}
	}

	if hasFailed {
		return hdf.Failed
	}
	if hasPassed {
		return hdf.Passed
	}
	if hasNotApplicable {
		return hdf.NotApplicable
	}
	return hdf.NotReviewed
}

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
	return hdfutil.ParseTimestamp(ts)
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
	} else if v1.SkipMessage != nil {
		// v1 skipped results carry their reason in skip_message; v2 has no
		// dedicated field, so surface it as the result message rather than
		// dropping it.
		v2.Message = v1.SkipMessage
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

// validSeverities maps lowercase severity strings to hdf.Severity values.
var validSeverities = map[string]hdf.Severity{
	"critical":      hdf.SeverityCritical,
	"high":          hdf.SeverityHigh,
	"medium":        hdf.SeverityMedium,
	"low":           hdf.SeverityLow,
	"informational": hdf.Informational,
}

// tagSeverityToSeverity extracts a valid severity from a tags map value.
// Returns nil if the value is not a recognized severity string.
func tagSeverityToSeverity(raw interface{}) *hdf.Severity {
	s, ok := raw.(string)
	if !ok {
		return nil
	}
	// strings.ToLower is already imported indirectly; use inline lowercase
	lower := ""
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			lower += string(c + 32)
		} else {
			lower += string(c)
		}
	}
	if sev, found := validSeverities[lower]; found {
		return &sev
	}
	return nil
}

// impactToSeverity derives severity from numeric impact score.
// Uses the canonical CVSS-aligned bands from hdfutil.ImpactToSeverity
// and converts the string result to the hdf.Severity enum.
func impactToSeverity(impact float64) hdf.Severity {
	return hdf.Severity(hdfutil.ImpactToSeverity(impact))
}

// toRef converts a v1 ref value (a string or an array of objects) to the v2
// Reference.Ref union. Returns nil when the value carries no content (e.g. an
// empty array), so callers can drop empty references.
func toRef(raw interface{}) *hdf.Ref {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		s := v
		return &hdf.Ref{String: &s}
	case []interface{}:
		maps := make([]map[string]interface{}, 0, len(v))
		for _, e := range v {
			if m, ok := e.(map[string]interface{}); ok {
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

// convertRef converts a single v1 refs[] element to a v2 Reference. v1 elements
// are either a bare string or an object with ref/url/uri keys. Returns nil when
// the element carries no usable content.
func convertRef(raw interface{}) *hdf.Reference {
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil
		}
		s := v
		return &hdf.Reference{Ref: &hdf.Ref{String: &s}}
	case map[string]interface{}:
		ref := &hdf.Reference{}
		has := false
		if r := toRef(v["ref"]); r != nil {
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

// convertRefs maps v1 control-level refs to v2 Requirement refs, dropping
// empty/contentless entries. Returns nil when nothing maps.
func convertRefs(refs []interface{}) []hdf.Reference {
	out := make([]hdf.Reference, 0, len(refs))
	for _, raw := range refs {
		if ref := convertRef(raw); ref != nil {
			out = append(out, *ref)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
	if v1.Refs != nil {
		v2.Refs = convertRefs(v1.Refs)
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

	// Derive controlType from any nist tags present in v1 tags. JSON
	// unmarshalling stores arrays as []interface{}, so normalize to []string
	// before passing to the shared helper.
	if v1.Tags != nil {
		if raw, ok := v1.Tags["nist"].([]interface{}); ok {
			nistStrs := make([]string, 0, len(raw))
			for _, v := range raw {
				if s, ok := v.(string); ok {
					nistStrs = append(nistStrs, s)
				}
			}
			if ct := shared.DeriveControlTypeFromTags(nistStrs); ct != nil {
				v2.ControlType = ct
			}
		} else if nistStrs, ok := v1.Tags["nist"].([]string); ok {
			if ct := shared.DeriveControlTypeFromTags(nistStrs); ct != nil {
				v2.ControlType = ct
			}
		}
	}

	// Transform results array
	if v1.Results != nil {
		v2.Results = make([]hdf.RequirementResult, len(v1.Results))
		for i, r := range v1.Results {
			v2.Results[i] = convertResult(r)
		}
	}

	// Always compute effectiveStatus when not explicitly set.
	// Uses InSpec enhanced outcomes precedence:
	// impact=0 → notApplicable, error > failed > passed > notApplicable > notReviewed
	if v2.EffectiveStatus == nil {
		es := computeEffectiveStatus(v1.Impact, v2.Results)
		v2.EffectiveStatus = &es
	}

	// Populate severity: prefer tags.severity (preserves original STIG severity),
	// fall back to impact-derived. InSpec sets impact=0 for NA controls, losing
	// the original severity — tags.severity preserves it.
	if v1.Tags != nil {
		if sev := tagSeverityToSeverity(v1.Tags["severity"]); sev != nil {
			v2.Severity = sev
		}
	}
	if v2.Severity == nil {
		sev := impactToSeverity(v1.Impact)
		v2.Severity = &sev
	}

	// verificationMethod is intentionally NOT set here. legacyhdf is a v1->v3
	// passthrough/upgrade converter; v1 HDF predates the verificationMethod
	// field, so the source carries no such signal. Stamping a value would
	// fabricate data not present in the input. A v1 control may have come
	// from an automated InSpec run OR a manual control (impact 0, no
	// describe block) — the v1 document does not record which.

	return v2
}

// convertAttributes converts v1.0 attributes to v2.0 Input structs.
// V1 attributes are generic maps of the form {"name": ..., "options": {...}};
// InSpec nests value/type/required/sensitive/description under "options".
func convertAttributes(attrs []map[string]interface{}) []hdf.Input {
	inputs := make([]hdf.Input, 0, len(attrs))
	for _, attr := range attrs {
		name, _ := attr["name"].(string)
		if name == "" {
			continue
		}
		input := hdf.Input{
			Name: name,
		}
		options, _ := attr["options"].(map[string]interface{})
		if options != nil {
			if val, exists := options["value"]; exists {
				input.Value = val
			}
			if desc, ok := options["description"].(string); ok {
				input.Description = &desc
			}
			if sensitive, ok := options["sensitive"].(bool); ok {
				input.Sensitive = &sensitive
			}
			if required, ok := options["required"].(bool); ok {
				input.Required = &required
			}
			if t, ok := options["type"].(string); ok {
				inputType := hdf.InputType(t)
				input.Type = &inputType
			}
		}
		inputs = append(inputs, input)
	}
	return inputs
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

// convertSupports maps v1 profile `supports` entries (InSpec hyphenated keys)
// to v2 SupportedPlatform structs. Entries that map no recognized key are
// dropped. Returns nil when nothing maps.
func convertSupports(supports []map[string]interface{}) []hdf.SupportedPlatform {
	out := make([]hdf.SupportedPlatform, 0, len(supports))
	for _, s := range supports {
		var sp hdf.SupportedPlatform
		has := false
		if v, ok := s["platform"].(string); ok && v != "" {
			sp.Platform = &v
			has = true
		}
		if v, ok := s["platform-family"].(string); ok && v != "" {
			sp.PlatformFamily = &v
			has = true
		}
		if v, ok := s["platform-name"].(string); ok && v != "" {
			sp.PlatformName = &v
			has = true
		}
		if v, ok := s["release"].(string); ok && v != "" {
			sp.Release = &v
			has = true
		}
		if has {
			out = append(out, sp)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

	// Transform sha256 to integrity object
	if v1.SHA256 != nil {
		alg := hdf.Sha256
		v2.Integrity = &hdf.Integrity{
			Algorithm: &alg,
			Checksum:  v1.SHA256,
		}
	}

	// Map supported platforms (InSpec hyphenated keys → v2 camelCase fields).
	if v1.Supports != nil {
		v2.Supports = convertSupports(v1.Supports)
	}

	// Transform attributes to inputs
	if v1.Attributes != nil {
		v2.Inputs = convertAttributes(v1.Attributes)
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

// inspecMajor parses the leading major-version integer from a version string,
// returning -1 when the string does not begin with an integer.
func inspecMajor(version string) int {
	i := 0
	for i < len(version) && version[i] >= '0' && version[i] <= '9' {
		i++
	}
	if i == 0 {
		return -1
	}
	n, err := strconv.Atoi(version[:i])
	if err != nil {
		return -1
	}
	return n
}

// toolIdentity maps the source's top-level version to tool metadata. A genuine
// InSpec exec-json run carries the InSpec CLI version (major >= 2 for every
// modern release), so those flip the tool to InSpec/exec-json. A legacy HDF v1
// document with no InSpec provenance (e.g. a bare "1.0.0" format marker) keeps
// the historical label.
func toolIdentity(version string) *hdf.Tool {
	if inspecMajor(version) >= 2 {
		name := "InSpec"
		v := version
		format := "exec-json"
		return &hdf.Tool{Name: &name, Version: &v, Format: &format}
	}
	name := "Heimdall Data Format v1"
	return &hdf.Tool{Name: &name}
}

// documentTimestamp returns the assessment's execution time for the top-level
// timestamp ("when this assessment was executed"). An explicit source timestamp
// wins; otherwise it is the latest (last-observed) result start_time — the
// assessment's effective as-of instant, and the value `hdf events derive`
// consumes as the next document's occurrence time. Returns nil only when the
// source carries no usable time; never the wall clock.
func documentTimestamp(v1 *HDFV1Results) *time.Time {
	if v1.Timestamp != nil {
		if t := hdfutil.ParseTimestamp(*v1.Timestamp); !t.IsZero() {
			return &t
		}
	}
	var latest time.Time
	for pi := range v1.Profiles {
		controls := v1.Profiles[pi].Controls
		for ci := range controls {
			for ri := range controls[ci].Results {
				st := controls[ci].Results[ri].StartTime
				if st == nil {
					continue
				}
				if t := hdfutil.ParseTimestamp(*st); !t.IsZero() && t.After(latest) {
					latest = t
				}
			}
		}
	}
	if latest.IsZero() {
		return nil
	}
	return &latest
}

// ConvertV1ToV2 converts HDF v1.0 results to v2.0 format.
//
// Performs comprehensive transformation at all levels:
//   - Top-level: version → tool/generator/timestamp, profiles → baselines, platform → targets
//   - Baselines: sha256 → checksum, controls → requirements, field renaming
//   - Requirements: snake_case → camelCase, status → effectiveStatus
//   - Results: snake_case → camelCase for all fields
func ConvertV1ToV2(v1 *HDFV1Results, converterVersion string) *hdf.HDFResults {
	if converterVersion == "" {
		converterVersion = "1.0.0" // mirrors the TS convertV1ToV2 default
	}
	generator := v1.Generator
	if generator == nil {
		generator = &hdf.Generator{Name: "legacyhdf-to-hdf", Version: converterVersion}
	}
	v2 := &hdf.HDFResults{
		Statistics: &hdf.Statistics{
			Duration: v1.Statistics.Duration,
		},
		Tool:      toolIdentity(v1.Version),
		Generator: generator,
		Timestamp: documentTimestamp(v1),
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
	target := hdf.Component{
		Type: hdf.Host,
		Name: v1.Platform.Name,
	}
	// Populate OS details whenever the platform carries an OS signal (a release
	// or a target_id). Previously gated on target_id alone, which dropped a
	// release-bearing platform that lacked a target_id.
	if v1.Platform.TargetID != nil || v1.Platform.Release != nil {
		target.OSName = &v1.Platform.Name // Use platform name as OS name
		target.OSVersion = v1.Platform.Release
	}
	v2.Components = []hdf.Component{target}

	// Flatten overlays: merge overlay/wrapper baselines so every requirement
	// has results and consumers don't see duplicated controls (741→247 fix).
	flat := hdfparsers.FlattenOverlays(*v2)
	return &flat.Results
}
