// Package hdfversion provides transforms between HDF schema versions.
// The router dispatches to registered transform functions, making it
// easy to add new versions without modifying the router itself.
package hdfversion

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	legacyhdf "github.com/mitre/hdf-libs/hdf-converters/v3/converters/legacyhdf-to-hdf/go"
	shared "github.com/mitre/hdf-libs/hdf-converters/v3/shared/go"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
	hdfutil "github.com/mitre/hdf-libs/hdf-utilities/go/v3"
)

// HDF schema version identifiers. The taxonomy: v1 is raw InSpec exec-json
// (not a distinct HDF schema — see NormalizeVersion); v2 is the legacy Heimdall
// schema (the profiles/platform shape the heimdall2 app loads); v3 is the
// modern hdf-libs schema (baselines/components).
//
// NOTE: the legacyhdf package's input structs (LegacyHDFResults/LegacyControl
// etc.) represent this v2 (legacy Heimdall) shape — the "Legacy" prefix replaced
// the earlier version-baked "V1" names. Within this file the transform function
// names and version strings use the corrected numbering (2 = legacy, 3 = modern).
const (
	// LegacyVersion is the legacy Heimdall HDF schema (profiles/platform).
	LegacyVersion = "2"
	// ModernVersion is the current hdf-libs schema (baselines/components).
	ModernVersion = "3"
)

// HDFVersionTransform converts HDF data from one schema version to another.
// The returned warnings name data that could not be represented in the target
// version (e.g. amendments with no v2 equivalent on a downgrade).
type HDFVersionTransform func(input []byte) ([]byte, []string, error)

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

// NormalizeVersion canonicalizes a user-supplied HDF version token. A leading "v"
// is accepted and stripped (users naturally write "v3"/"v2"). "1" has no distinct
// schema, so it maps to v2 (legacy) and returns NoV1Warning; "2" and "3" (and "")
// pass through with no warning. Callers should apply this only when the format is
// hdf, and print the returned warning (if any) once.
func NormalizeVersion(v string) (canonical, warning string) {
	v = strings.TrimPrefix(v, "v")
	if v == "1" {
		return LegacyVersion, NoV1Warning
	}
	return v, ""
}

// TransformHDF converts HDF data between schema versions using the registered
// transform registry. Returns the input unchanged when fromVersion == toVersion.
// Returns an error for unknown version pairs.
func TransformHDF(input []byte, fromVersion, toVersion string) ([]byte, []string, error) {
	if fromVersion == toVersion {
		return input, nil, nil
	}

	key := [2]string{fromVersion, toVersion}
	transform, ok := hdfTransforms[key]
	if !ok {
		return nil, nil, fmt.Errorf("no HDF transform registered for %s → %s", fromVersion, toVersion)
	}

	return transform(input)
}

// upgradeV2ToV3 converts the legacy Heimdall HDF schema (v2, the InSpec
// exec-json profiles/platform shape) to modern HDF (v3). Delegates to the
// legacyhdf converter (IsLegacyHDF / ConvertLegacyHDF).
func upgradeV2ToV3(input []byte) ([]byte, []string, error) {
	if !legacyhdf.IsLegacyHDF(input) {
		return nil, nil, fmt.Errorf("input is not the legacy HDF (v2) shape")
	}

	var legacy legacyhdf.LegacyHDFResults
	if err := json.Unmarshal(input, &legacy); err != nil {
		return nil, nil, fmt.Errorf("failed to parse legacy HDF (v2): %w", err)
	}

	modern := legacyhdf.ConvertLegacyHDF(&legacy, "")
	out, err := json.MarshalIndent(modern, "", "  ")
	return out, nil, err
}

// downgradeV3ToV2 converts modern HDF (v3) to the legacy Heimdall schema (v2,
// the InSpec exec-json shape). Status-changing amendments (waiver, attestation,
// falsePositive, inherited) are flattened into the v2 control status with an audit
// breadcrumb in waiver_data, so Heimdall shows the attested outcome; the raw
// results[].status verdict is preserved. Amendments with no v2 equivalent (poam,
// operationalRequirement) cannot be represented and are named in the warnings.
//
// Structured vulnerability fields (cwe, cvss severity) are mirrored into tags so
// they survive and display in Heimdall; refs are carried into the v2 refs slot.
// Lossy fields with no v2 carrier: dataSource, generator (except version), labels,
// root amendments, checksum metadata, components beyond the first, evidence,
// poam/operationalRequirement state, result resource_params, and the remaining
// structured vuln data (cvss score/vector, epss, kev, affectedPackages).
func downgradeV3ToV2(input []byte) ([]byte, []string, error) {
	var modern hdf.HDFResults
	if err := json.Unmarshal(input, &modern); err != nil {
		return nil, nil, fmt.Errorf("failed to parse modern HDF (v3): %w", err)
	}

	legacy, warnings := convertV3ToV2(&modern)
	out, err := json.MarshalIndent(legacy, "", "  ")
	return out, warnings, err
}

// convertV3ToV2 maps the modern HDF (v3) structure back to the legacy (v2) shape,
// returning warnings for amendments that could not be represented.
func convertV3ToV2(v2 *hdf.HDFResults) (*legacyhdf.LegacyHDFResults, []string) {
	// Top-level version — Heimdall's InSpec fingerprint may key on it, and the
	// upgrade path drops it, so reconstruct from the source tool / generator.
	v1 := &legacyhdf.LegacyHDFResults{Version: downgradeVersion(v2)}

	// Map components → platform (use first component). name + release are required by
	// the InSpec exec-json schema Heimdall loads, so release is always present (the
	// empty string when no OS version is known).
	release := ""
	if len(v2.Components) > 0 {
		t := v2.Components[0]
		v1.Platform.Name = t.Name
		if t.OSVersion != nil {
			release = *t.OSVersion
		}
		if t.Name != "" {
			targetID := t.Name
			v1.Platform.TargetID = &targetID
		}
	}
	v1.Platform.Release = &release

	// Map statistics
	if v2.Statistics != nil {
		v1.Statistics = legacyhdf.LegacyStatistics{
			Duration: v2.Statistics.Duration,
		}
	}

	// Map baselines → profiles
	var warnings []string
	v1.Profiles = make([]legacyhdf.LegacyProfile, len(v2.Baselines))
	for i, baseline := range v2.Baselines {
		p, w := convertBaselineToV2Profile(baseline)
		v1.Profiles[i] = p
		warnings = append(warnings, w...)
	}

	return v1, warnings
}

// downgradeVersion reconstructs the legacy top-level version string, preferring
// the source tool version, then the generator version, then a sentinel.
func downgradeVersion(v3 *hdf.HDFResults) string {
	if v3.Tool != nil && v3.Tool.Version != nil && *v3.Tool.Version != "" {
		return *v3.Tool.Version
	}
	if v3.Generator != nil && v3.Generator.Version != "" {
		return v3.Generator.Version
	}
	return "0.0.0"
}

// convertBaselineToV2Profile maps an EvaluatedBaseline back to a LegacyProfile,
// returning warnings for any non-representable amendments on its requirements.
func convertBaselineToV2Profile(b hdf.EvaluatedBaseline) (legacyhdf.LegacyProfile, []string) {
	p := legacyhdf.LegacyProfile{
		Name:    b.Name,
		Version: b.Version,
		Title:   b.Title,
	}

	// InSpec-required fields the modern baseline has no equivalent for: supports and
	// attributes are always-present (possibly empty) arrays. Groups is set below.
	p.Supports = make([]map[string]interface{}, 0)
	p.Attributes = make([]map[string]interface{}, 0)

	// sha256 is InSpec-required and Heimdall matches the profile fingerprint on it.
	// Prefer the baseline integrity hash (where an inspec profile's sha256 round-trips),
	// then the results/original checksums, else empty.
	sha := ""
	switch {
	case b.Integrity != nil && b.Integrity.Checksum != nil && *b.Integrity.Checksum != "":
		sha = *b.Integrity.Checksum
	case b.ResultsChecksum != nil && b.ResultsChecksum.Value != "":
		sha = b.ResultsChecksum.Value
	case b.OriginalChecksum != nil && b.OriginalChecksum.Value != "":
		sha = b.OriginalChecksum.Value
	}
	p.SHA256 = &sha

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
	p.Groups = make([]legacyhdf.LegacyGroup, len(b.Groups))
	for i, g := range b.Groups {
		p.Groups[i] = legacyhdf.LegacyGroup{
			ID:       g.ID,
			Title:    g.Title,
			Controls: g.Requirements,
		}
	}

	// Map dependencies
	p.Depends = make([]legacyhdf.LegacyDependency, len(b.Depends))
	for i, d := range b.Depends {
		p.Depends[i] = convertDependencyToV2(d)
	}

	// Map requirements → controls
	var warnings []string
	p.Controls = make([]legacyhdf.LegacyControl, len(b.Requirements))
	for i, r := range b.Requirements {
		c, w := convertRequirementToV2Control(r)
		p.Controls[i] = c
		warnings = append(warnings, w...)
	}

	return p, warnings
}

// convertDependencyToV2 maps a Dependency to LegacyDependency.
func convertDependencyToV2(d hdf.Dependency) legacyhdf.LegacyDependency {
	return legacyhdf.LegacyDependency{
		Name: d.Name,
		URL:  d.URL,
		Path: d.Path,
		Git:  d.Git,
	}
}

// convertRequirementToV2Control maps an EvaluatedRequirement to a LegacyControl,
// flattening status-changing amendments into the control status + waiver_data
// and returning warnings for amendments with no v2 equivalent.
func convertRequirementToV2Control(r hdf.EvaluatedRequirement) (legacyhdf.LegacyControl, []string) {
	c := legacyhdf.LegacyControl{
		ID:     r.ID,
		Title:  r.Title,
		Impact: r.Impact,
		Code:   r.Code,
	}

	// riskAdjustment (and any impact override) re-scores the displayed impact.
	if r.EffectiveImpact != nil {
		c.Impact = *r.EffectiveImpact
	}

	// Extract default description as desc
	for _, d := range r.Descriptions {
		if d.Label == "default" {
			desc := d.Data
			c.Desc = &desc
			break
		}
	}

	// Map tags — always present ({} when empty); the InSpec schema requires the key.
	c.Tags = make(map[string]interface{}, len(r.Tags))
	for k, v := range r.Tags {
		c.Tags[k] = v
	}

	// Map descriptions
	c.Descriptions = make([]legacyhdf.LegacyDescription, len(r.Descriptions))
	for i, d := range r.Descriptions {
		c.Descriptions[i] = legacyhdf.LegacyDescription{
			Label: d.Label,
			Data:  d.Data,
		}
	}

	// Map source location — required by the InSpec schema (an empty object is valid).
	sl := legacyhdf.LegacySourceLocation{}
	if r.SourceLocation != nil {
		sl.Ref = r.SourceLocation.Ref
		if r.SourceLocation.Line != nil {
			line := int(*r.SourceLocation.Line)
			sl.Line = &line
		}
	}
	c.SourceLocation = &sl

	// Carry advisory references into the (required) v2 refs array — empty is valid.
	refs := make([]interface{}, len(r.Refs))
	for i, ref := range r.Refs {
		refs[i] = ref
	}
	c.Refs = refs

	// Mirror structured vulnerability fields (modern-only typed fields with no other v2
	// carrier) into tags so they survive the downgrade and display in Heimdall, which
	// reads tags.cweid / tags.severity. Never overwrite an existing tag.
	if len(r.Cwe) > 0 || len(r.Cvss) > 0 {
		if c.Tags == nil {
			c.Tags = map[string]interface{}{}
		}
		if _, ok := c.Tags["cweid"]; !ok && len(r.Cwe) > 0 {
			c.Tags["cweid"] = r.Cwe
		}
		if _, ok := c.Tags["severity"]; !ok {
			if sev := firstCVSSSeverity(r.Cvss); sev != "" {
				c.Tags["severity"] = sev
			}
		}
	}

	// Control-level status carries the EFFECTIVE (post-amendment) outcome so Heimdall
	// shows the attested result; the raw per-result verdict is preserved below. Falls
	// back to the worst-wins rollup when no effectiveStatus is present.
	status := effectiveOrRollup(r)
	c.Status = &status

	// Flatten a status-changing amendment (and note any non-representable ones) into
	// the waiver_data breadcrumb so the override is recoverable in the v2 document.
	if wd := buildWaiverData(r); wd != nil {
		c.WaiverData = wd
	}
	warnings := nonRepresentableWarnings(r)

	// Map results (raw verdict preserved; carry InSpec resource fields where present).
	c.Results = make([]legacyhdf.LegacyResult, len(r.Results))
	for i, res := range r.Results {
		c.Results[i] = convertResultToV2(res)
	}

	return c, warnings
}

// firstCVSSSeverity returns the base severity of the first CVSS entry that has one.
func firstCVSSSeverity(cvss []hdf.Cvss) string {
	for _, c := range cvss {
		if c.BaseSeverity != nil && *c.BaseSeverity != "" {
			return string(*c.BaseSeverity)
		}
	}
	return ""
}

// effectiveOrRollup returns the v1 status string for a requirement's
// effective status, computed by the canonical shared helper in hdf-utilities
// (impact==0, governing override, stored effectiveStatus, worst-wins rollup —
// see status-determination.md).
func effectiveOrRollup(r hdf.EvaluatedRequirement) string {
	input := shared.RequirementStatusInput(r)
	return v2StatusString(hdf.ResultStatus(hdfutil.ComputeEffectiveStatus(input, time.Time{})))
}

// governingOverride returns the override that drives effectiveStatus (the
// most-recently-applied non-expired status-bearing one, per the canonical
// selection in hdf-utilities), or nil if there is none. An expired override
// must not become the waiver_data breadcrumb.
func governingOverride(r hdf.EvaluatedRequirement) *hdf.StatusOverride {
	inputs := shared.StatusOverrideInputs(r.StatusOverrides)
	if i := hdfutil.GoverningStatusOverrideIndex(inputs, time.Time{}); i >= 0 {
		return &r.StatusOverrides[i]
	}
	return nil
}

// buildWaiverData renders the governing override (and any non-representable
// amendment) as a free-form v1 waiver_data breadcrumb, or nil when the
// requirement carries no amendments.
func buildWaiverData(r hdf.EvaluatedRequirement) map[string]interface{} {
	wd := map[string]interface{}{}
	if gov := governingOverride(r); gov != nil {
		wd["skipped_due_to_waiver"] = true
		wd["override_type"] = string(gov.Type)
		wd["message"] = gov.Reason
		// A zero ExpiresAt means the override never expires (per the shared
		// selection helper); "0001-01-01" would read as long-expired.
		if !gov.ExpiresAt.IsZero() {
			wd["expiration_date"] = gov.ExpiresAt.Format(time.RFC3339)
		}
		wd["applied_by"] = gov.AppliedBy.Identifier
	}
	// Best-effort breadcrumb for amendments that have no v2 status equivalent.
	var notRepresentable []string
	for _, p := range r.Poams {
		notRepresentable = append(notRepresentable, "poam:"+string(p.Type))
	}
	for i := range r.StatusOverrides {
		if r.StatusOverrides[i].Type == hdf.OperationalRequirement {
			notRepresentable = append(notRepresentable, "operationalRequirement")
		}
	}
	if len(notRepresentable) > 0 {
		wd["not_representable_in_v2"] = notRepresentable
	}
	if len(wd) == 0 {
		return nil
	}
	return wd
}

// nonRepresentableWarnings names amendments that cannot be represented in the v2
// (legacy) shape: POA&Ms and operationalRequirement overrides both leave a
// finding open, which v2 has no field for.
func nonRepresentableWarnings(r hdf.EvaluatedRequirement) []string {
	var w []string
	for _, p := range r.Poams {
		w = append(w, fmt.Sprintf("control %q: POA&M (%s) has no HDF v2 equivalent — its open/remediation-tracked state is not represented (breadcrumb in waiver_data)", r.ID, p.Type))
	}
	for i := range r.StatusOverrides {
		if r.StatusOverrides[i].Type == hdf.OperationalRequirement {
			w = append(w, fmt.Sprintf("control %q: operationalRequirement amendment has no HDF v2 equivalent — its accepted-open-risk state is not represented (breadcrumb in waiver_data)", r.ID))
		}
	}
	return w
}

// convertResultToV2 maps a RequirementResult to a LegacyResult.
func convertResultToV2(r hdf.RequirementResult) legacyhdf.LegacyResult {
	v1r := legacyhdf.LegacyResult{
		Status:  v2StatusString(r.Status),
		Message: r.Message,
	}

	// CodeDesc is required in v2 but was pointer in v1
	codeDesc := r.CodeDesc
	v1r.CodeDesc = &codeDesc

	if r.RunTime != nil {
		v1r.RunTime = r.RunTime
	}

	// start_time is required by the InSpec exec-json schema Heimdall loads, so always
	// present; fall back to the zero-value timestamp when the modern result has none.
	st := "0001-01-01T00:00:00Z"
	if !r.StartTime.IsZero() {
		st = r.StartTime.Format(time.RFC3339)
	}
	v1r.StartTime = &st

	if r.Exception != nil {
		v1r.Exception = r.Exception
	}
	if len(r.Backtrace) > 0 {
		v1r.Backtrace = r.Backtrace
	}

	// Carry the InSpec resource fields where the modern result preserved them
	// (resource type → resource_class; resource_params has no v3 equivalent).
	if r.Resource != nil {
		v1r.ResourceClass = r.Resource
	}
	if r.ResourceID != nil {
		v1r.ResourceID = r.ResourceID
	}

	return v1r
}

// v2StatusString maps a modern ResultStatus to a v1 InSpec exec-json result status.
// InSpec's ControlResultStatus enum is only passed/failed/error/skipped (what
// Heimdall accepts), so notApplicable and notReviewed both collapse to skipped.
func v2StatusString(s hdf.ResultStatus) string {
	switch s {
	case hdf.Passed:
		return "passed"
	case hdf.Failed:
		return "failed"
	case hdf.Error:
		return "error"
	default:
		return "skipped"
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
