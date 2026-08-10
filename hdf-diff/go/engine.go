// Package diff provides the core diff engine for comparing HDF evaluation documents.
// It is a direct port of the TypeScript implementation in hdf-diff/src/diff.ts.
package diff

import (
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/mitre/hdf-libs/hdf-diff/go/v3/matching"
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// Field name constants for tracked field configuration and lookups.
const (
	fieldNameImpact       = "impact"
	fieldNameSeverity     = "severity"
	fieldNameTags         = "tags"
	fieldNameTitle        = "title"
	fieldNameDescriptions = "descriptions"
)

// defaultMatchStrategy is the default matching strategy when none is specified.
const defaultMatchStrategy = "exactId"

// defaultTrackedFields is the default set of fields to track for field-level diffs.
var defaultTrackedFields = []string{fieldNameImpact, fieldNameSeverity, fieldNameTags}

// Options configures the comparison behavior.
type Options struct {
	TrackedFields      []string
	ComparisonMode     ComparisonMode
	MatchStrategy      string
	FallbackStrategies []string
	MappingTable       map[string]string
	MinConfidence      float64
}

// resolveOptions fills in default values for any zero-value fields in the options.
func resolveOptions(opts Options) Options {
	if len(opts.TrackedFields) == 0 {
		opts.TrackedFields = defaultTrackedFields
	}
	if opts.ComparisonMode == "" {
		opts.ComparisonMode = ModeTemporal
	}
	if opts.MatchStrategy == "" {
		opts.MatchStrategy = defaultMatchStrategy
	}
	return opts
}

// buildMatchOptions converts engine Options to matching.Options.
func buildMatchOptions(opts Options) matching.Options {
	return matching.Options{
		Strategy:           opts.MatchStrategy,
		FallbackStrategies: opts.FallbackStrategies,
		MappingTable:       opts.MappingTable,
		MinConfidence:      opts.MinConfidence,
	}
}

// DiffHdf compares two HDF results documents and produces a structured comparison.
// For fleet mode, newResults can contain multiple HdfResults (one per system).
// Returns an error if the match strategy is invalid.
//
//nolint:revive // matches TypeScript export name
func DiffHdf(oldResults hdf.HDFResults, newResults []hdf.HDFResults, opts Options) (HdfComparison, error) {
	opts = resolveOptions(opts)
	matchOpts := buildMatchOptions(opts)

	if opts.ComparisonMode == ModeFleet {
		return diffFleet(oldResults, newResults, opts, matchOpts)
	}

	// Non-fleet modes: use first element of newResults
	var newDoc hdf.HDFResults
	if len(newResults) > 0 {
		newDoc = newResults[0]
	}

	// Build sources metadata
	sources := buildSources(opts.ComparisonMode)

	// Extract timestamps from documents for override expiration checks
	oldTimestamp := formatTimestamp(oldResults.Timestamp)
	newTimestamp := formatTimestamp(newDoc.Timestamp)

	// Compute baseline and requirement diffs
	baselineDiffs, requirementDiffs, err := comparePair(oldResults, newDoc, oldTimestamp, newTimestamp, opts.TrackedFields, matchOpts)
	if err != nil {
		return HdfComparison{}, err
	}

	// Sort by ID
	sort.Slice(requirementDiffs, func(i, j int) bool {
		return requirementDiffs[i].ID < requirementDiffs[j].ID
	})

	// Extract drift
	drift := extractDrift(requirementDiffs)

	return HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   opts.ComparisonMode,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &MatchingConfig{PrimaryStrategy: opts.MatchStrategy},
		Summary:          ComputeSummary(requirementDiffs),
		BaselineDiffs:    baselineDiffs,
		RequirementDiffs: requirementDiffs,
		Drift:            drift,
	}, nil
}

// buildSources creates source metadata entries based on comparison mode.
func buildSources(mode ComparisonMode) []Source {
	if mode == ModeBaseline {
		return []Source{
			{Role: RoleGolden, Label: "Golden baseline"},
			{Role: RoleNew, Label: "Current scan"},
		}
	}
	return []Source{
		{Role: RoleOld, Label: "Old evaluation"},
		{Role: RoleNew, Label: "New evaluation"},
	}
}

// diffFleet compares a reference document against one or more system documents.
func diffFleet(
	reference hdf.HDFResults,
	systems []hdf.HDFResults,
	opts Options,
	matchOpts matching.Options,
) (HdfComparison, error) {
	sources := []Source{
		{Role: RoleReference, Label: "Reference"},
	}

	var allRequirementDiffs []RequirementDiff
	var allBaselineDiffs []BaselineDiff
	seenBaselineNames := make(map[string]bool)

	refTimestamp := formatTimestamp(reference.Timestamp)

	for i, sys := range systems {
		sourceIndex := i + 1

		sources = append(sources, Source{
			Role:  RoleSystem,
			Label: "System " + strconv.Itoa(sourceIndex),
		})

		sysTimestamp := formatTimestamp(sys.Timestamp)
		baselineDiffs, requirementDiffs, err := comparePair(reference, sys, refTimestamp, sysTimestamp, opts.TrackedFields, matchOpts)
		if err != nil {
			return HdfComparison{}, err
		}

		// Tag each requirement diff with its source index
		for j := range requirementDiffs {
			idx := sourceIndex
			requirementDiffs[j].SourceIndex = &idx
			allRequirementDiffs = append(allRequirementDiffs, requirementDiffs[j])
		}

		// Collect baseline diffs (first-wins dedup)
		for _, bd := range baselineDiffs {
			if !seenBaselineNames[bd.Name] {
				seenBaselineNames[bd.Name] = true
				allBaselineDiffs = append(allBaselineDiffs, bd)
			}
		}
	}

	// Sort by ID, then by sourceIndex
	sort.Slice(allRequirementDiffs, func(i, j int) bool {
		if allRequirementDiffs[i].ID != allRequirementDiffs[j].ID {
			return allRequirementDiffs[i].ID < allRequirementDiffs[j].ID
		}
		iIdx := 0
		jIdx := 0
		if allRequirementDiffs[i].SourceIndex != nil {
			iIdx = *allRequirementDiffs[i].SourceIndex
		}
		if allRequirementDiffs[j].SourceIndex != nil {
			jIdx = *allRequirementDiffs[j].SourceIndex
		}
		return iIdx < jIdx
	})

	drift := extractDrift(allRequirementDiffs)

	return HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   ModeFleet,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &MatchingConfig{PrimaryStrategy: opts.MatchStrategy},
		Summary:          ComputeSummary(allRequirementDiffs),
		BaselineDiffs:    allBaselineDiffs,
		RequirementDiffs: allRequirementDiffs,
		Drift:            drift,
	}, nil
}

// comparePair performs the core pairwise comparison between two HDF result documents.
// oldTimestamp and newTimestamp are RFC3339 strings from the source documents, used
// to evaluate override expiration relative to each document's assessment time.
func comparePair(
	oldDoc, newDoc hdf.HDFResults,
	oldTimestamp, newTimestamp string,
	trackedFields []string,
	matchOpts matching.Options,
) ([]BaselineDiff, []RequirementDiff, error) {
	// Build baseline maps by name
	oldBaselineMap := make(map[string]hdf.EvaluatedBaseline)
	for _, b := range oldDoc.Baselines {
		oldBaselineMap[b.Name] = b
	}
	newBaselineMap := make(map[string]hdf.EvaluatedBaseline)
	for _, b := range newDoc.Baselines {
		newBaselineMap[b.Name] = b
	}

	// Compute baseline diffs
	allBaselineNames := make(map[string]bool)
	for name := range oldBaselineMap {
		allBaselineNames[name] = true
	}
	for name := range newBaselineMap {
		allBaselineNames[name] = true
	}

	var baselineDiffs []BaselineDiff
	for name := range allBaselineNames {
		oldB, oldExists := oldBaselineMap[name]
		newB, newExists := newBaselineMap[name]

		switch {
		case oldExists && newExists:
			oldVer := derefStr(oldB.Version)
			newVer := derefStr(newB.Version)
			state := StateUnchanged
			if oldVer != newVer {
				state = StateUpdated
			}
			baselineDiffs = append(baselineDiffs, BaselineDiff{
				Name:       name,
				OldVersion: oldVer,
				NewVersion: newVer,
				State:      state,
			})
		case oldExists:
			baselineDiffs = append(baselineDiffs, BaselineDiff{
				Name:       name,
				OldVersion: derefStr(oldB.Version),
				State:      StateAbsent,
			})
		case newExists:
			baselineDiffs = append(baselineDiffs, BaselineDiff{
				Name:       name,
				NewVersion: derefStr(newB.Version),
				State:      StateNew,
			})
		}
	}

	// Build requirement ID → baseline name maps for populating RequirementDiff.Baseline
	oldReqBaselineMap := requirementBaselineMap(oldDoc)
	newReqBaselineMap := requirementBaselineMap(newDoc)

	var oldReqs []hdf.EvaluatedRequirement
	for _, baseline := range oldDoc.Baselines {
		oldReqs = append(oldReqs, baseline.Requirements...)
	}
	var newReqs []hdf.EvaluatedRequirement
	for _, baseline := range newDoc.Baselines {
		newReqs = append(newReqs, baseline.Requirements...)
	}

	// Use the matching system to pair requirements
	matchResult, err := matching.MatchRequirementsWithError(oldReqs, newReqs, matchOpts)
	if err != nil {
		return nil, nil, err
	}

	// Build requirement diffs from match results
	var requirementDiffs []RequirementDiff

	// Matched pairs
	for _, pair := range matchResult.Matched {
		id := pair.NewReq.ID
		if id == "" {
			id = pair.OldReq.ID
		}

		oldStatus := ComputeEffectiveStatus(pair.OldReq, oldTimestamp)
		newStatus := ComputeEffectiveStatus(pair.NewReq, newTimestamp)

		diffState := ClassifyDiffStatus(oldStatus, newStatus)
		changeReasons := ClassifyChangeReasons(pair.OldReq, pair.NewReq, oldTimestamp, newTimestamp)

		fieldChanges := computeFieldChanges(pair.OldReq, pair.NewReq, trackedFields)

		// Resolve title: prefer newReq title, fall back to oldReq title
		title := resolveTitle(pair.OldReq.Title, pair.NewReq.Title)

		oldImpact := pair.OldReq.Impact
		newImpact := pair.NewReq.Impact
		confidence := pair.Confidence

		oldReqCopy := pair.OldReq
		newReqCopy := pair.NewReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:                 id,
			Title:              title,
			Baseline:           resolveBaseline(id, newReqBaselineMap, oldReqBaselineMap),
			State:              diffState,
			OldEffectiveStatus: oldStatus,
			NewEffectiveStatus: newStatus,
			ChangeReasons:      changeReasons,
			OldImpact:          &oldImpact,
			NewImpact:          &newImpact,
			FieldChanges:       fieldChanges,
			Before:             &oldReqCopy,
			After:              &newReqCopy,
			MatchStrategy:      pair.Strategy,
			MatchConfidence:    &confidence,
		})
	}

	// Unmatched old requirements (absent)
	for _, oldReq := range matchResult.UnmatchedOld {
		oldStatus := ComputeEffectiveStatus(oldReq, oldTimestamp)
		title := resolveTitle(oldReq.Title, nil)
		oldImpact := oldReq.Impact
		oldReqCopy := oldReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:                 oldReq.ID,
			Title:              title,
			Baseline:           resolveBaseline(oldReq.ID, newReqBaselineMap, oldReqBaselineMap),
			State:              StateAbsent,
			OldEffectiveStatus: oldStatus,
			ChangeReasons:      []ChangeReason{},
			OldImpact:          &oldImpact,
			FieldChanges:       []FieldChange{},
			Before:             &oldReqCopy,
			After:              nil,
		})
	}

	// Unmatched new requirements (new)
	for _, newReq := range matchResult.UnmatchedNew {
		newStatus := ComputeEffectiveStatus(newReq, newTimestamp)
		title := resolveTitle(nil, newReq.Title)
		newImpact := newReq.Impact
		newReqCopy := newReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:                 newReq.ID,
			Title:              title,
			Baseline:           resolveBaseline(newReq.ID, newReqBaselineMap, oldReqBaselineMap),
			State:              StateNew,
			NewEffectiveStatus: newStatus,
			ChangeReasons:      []ChangeReason{},
			NewImpact:          &newImpact,
			FieldChanges:       []FieldChange{},
			Before:             nil,
			After:              &newReqCopy,
		})
	}

	return baselineDiffs, requirementDiffs, nil
}

// extractDrift returns requirements whose effective status is unchanged but whose
// metadata changed (non-empty changeReasons). These are "silent" changes.
func extractDrift(requirementDiffs []RequirementDiff) []RequirementDiff {
	var drift []RequirementDiff
	for _, r := range requirementDiffs {
		if r.State == StateUnchanged && len(r.ChangeReasons) > 0 {
			driftEntry := r
			drift = append(drift, driftEntry)
		}
	}
	return drift
}

// computeFieldChanges computes field-level changes between two requirements
// for the specified tracked fields. Uses reflect.DeepEqual for key-order-independent
// comparison (replacing the previous JSON serialization approach).
func computeFieldChanges(
	oldReq, newReq hdf.EvaluatedRequirement,
	trackedFields []string,
) []FieldChange {
	// Non-nil: Requirement_Diff.fieldChanges is a required array in the
	// schema; nil marshals as null and fails validation.
	changes := []FieldChange{}

	for _, field := range trackedFields {
		oldVal := getFieldValue(oldReq, field)
		newVal := getFieldValue(newReq, field)

		if !reflect.DeepEqual(oldVal, newVal) {
			oldIsZero := isZeroValue(oldVal)
			newIsZero := isZeroValue(newVal)

			switch {
			case oldIsZero && !newIsZero:
				changes = append(changes, FieldChange{
					Op:       OpAdd,
					Path:     field,
					NewValue: newVal,
				})
			case !oldIsZero && newIsZero:
				changes = append(changes, FieldChange{
					Op:       OpRemove,
					Path:     field,
					OldValue: oldVal,
				})
			default:
				changes = append(changes, FieldChange{
					Op:       OpReplace,
					Path:     field,
					OldValue: oldVal,
					NewValue: newVal,
				})
			}
		}
	}

	return changes
}

// getFieldValue extracts a field value from an EvaluatedRequirement by field name.
func getFieldValue(req hdf.EvaluatedRequirement, field string) any {
	switch field {
	case fieldNameImpact:
		return req.Impact
	case fieldNameSeverity:
		if req.Severity == nil {
			return nil
		}
		return string(*req.Severity)
	case fieldNameTags:
		return req.Tags
	case fieldNameTitle:
		if req.Title == nil {
			return nil
		}
		return *req.Title
	case fieldNameDescriptions:
		return req.Descriptions
	default:
		return nil
	}
}

// isZeroValue checks if a value is nil (representing an absent field).
// Numeric zero values (0, 0.0) are NOT considered absent -- they are valid values.
// Only nil interface values and nil pointers/maps/slices count as absent.
func isZeroValue(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return true
	}
	//nolint:exhaustive // Only nilable kinds need special handling; scalars return false.
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface:
		return rv.IsNil()
	case reflect.Map, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

// resolveTitle returns the title from newReq if set, otherwise from oldReq.
func resolveTitle(oldTitle, newTitle *string) string {
	if newTitle != nil {
		return *newTitle
	}
	if oldTitle != nil {
		return *oldTitle
	}
	return ""
}

// formatTimestamp converts a *time.Time to an RFC3339 string, or "" if nil.
func formatTimestamp(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Format(time.RFC3339)
}

// derefStr returns the string value of a *string, or "" if nil.
func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// defaultBaselineTrackedFields is the set of fields tracked for baseline evolution diffs.
var defaultBaselineTrackedFields = []string{fieldNameTitle, fieldNameImpact, fieldNameDescriptions, fieldNameTags}

// DiffBaselines compares two HDF baseline documents and produces a structured comparison
// showing requirement changes between baseline versions.
//
// Unlike DiffHdf (which compares evaluation results), this compares baseline definitions —
// requirements without results. There is no status-based classification (fixed/regressed);
// only metadata changes (title, impact, descriptions, tags) are tracked.
//
//nolint:revive // matches TypeScript export name
func DiffBaselines(oldBaseline, newBaseline hdf.HDFBaseline, opts Options) (HdfComparison, error) {
	trackedFields := opts.TrackedFields
	if len(trackedFields) == 0 {
		trackedFields = defaultBaselineTrackedFields
	}
	matchStrategy := opts.MatchStrategy
	if matchStrategy == "" {
		matchStrategy = defaultMatchStrategy
	}
	matchOpts := buildMatchOptions(opts)

	// Convert baseline requirements to EvaluatedRequirement for matching compatibility
	oldReqs := baselineReqsToEvaluated(oldBaseline.Requirements)
	newReqs := baselineReqsToEvaluated(newBaseline.Requirements)

	// Use the matching system to pair requirements
	matchResult, err := matching.MatchRequirementsWithError(oldReqs, newReqs, matchOpts)
	if err != nil {
		return HdfComparison{}, err
	}

	// Build requirement diffs from match results
	var requirementDiffs []RequirementDiff

	// Matched pairs
	for _, pair := range matchResult.Matched {
		id := pair.NewReq.ID
		if id == "" {
			id = pair.OldReq.ID
		}

		fieldChanges := computeFieldChanges(pair.OldReq, pair.NewReq, trackedFields)

		// For baseline evolution, state is determined by metadata changes only
		state := StateUnchanged
		if len(fieldChanges) > 0 {
			state = StateUpdated
		}

		// Determine change reasons
		changeReasons := classifyBaselineChangeReasons(pair.OldReq, pair.NewReq)

		title := resolveTitle(pair.OldReq.Title, pair.NewReq.Title)
		oldImpact := pair.OldReq.Impact
		newImpact := pair.NewReq.Impact
		confidence := pair.Confidence

		oldReqCopy := pair.OldReq
		newReqCopy := pair.NewReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:              id,
			Title:           title,
			State:           state,
			ChangeReasons:   changeReasons,
			OldImpact:       &oldImpact,
			NewImpact:       &newImpact,
			FieldChanges:    fieldChanges,
			Before:          &oldReqCopy,
			After:           &newReqCopy,
			MatchStrategy:   pair.Strategy,
			MatchConfidence: &confidence,
		})
	}

	// Unmatched old requirements (absent)
	for _, oldReq := range matchResult.UnmatchedOld {
		title := resolveTitle(oldReq.Title, nil)
		oldImpact := oldReq.Impact
		oldReqCopy := oldReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:            oldReq.ID,
			Title:         title,
			State:         StateAbsent,
			ChangeReasons: []ChangeReason{},
			OldImpact:     &oldImpact,
			FieldChanges:  []FieldChange{},
			Before:        &oldReqCopy,
			After:         nil,
		})
	}

	// Unmatched new requirements (new)
	for _, newReq := range matchResult.UnmatchedNew {
		title := resolveTitle(nil, newReq.Title)
		newImpact := newReq.Impact
		newReqCopy := newReq

		requirementDiffs = append(requirementDiffs, RequirementDiff{
			ID:            newReq.ID,
			Title:         title,
			State:         StateNew,
			ChangeReasons: []ChangeReason{},
			NewImpact:     &newImpact,
			FieldChanges:  []FieldChange{},
			Before:        nil,
			After:         &newReqCopy,
		})
	}

	// Sort by ID
	sort.Slice(requirementDiffs, func(i, j int) bool {
		return requirementDiffs[i].ID < requirementDiffs[j].ID
	})

	// Build baseline diff from top-level metadata
	oldName := oldBaseline.Name
	newName := newBaseline.Name
	oldVersion := derefStr(oldBaseline.Version)
	newVersion := derefStr(newBaseline.Version)

	var baselineDiffs []BaselineDiff
	baselineName := newName
	if baselineName == "" {
		baselineName = oldName
	}
	if baselineName != "" {
		state := StateUnchanged
		if oldVersion != newVersion {
			state = StateUpdated
		}
		baselineDiffs = append(baselineDiffs, BaselineDiff{
			Name:       baselineName,
			OldVersion: oldVersion,
			NewVersion: newVersion,
			State:      state,
		})
	}

	// Build sources
	oldLabel := baselineName
	if oldVersion != "" {
		oldLabel = baselineName + " " + oldVersion
	}
	if oldLabel == "" {
		oldLabel = "Old baseline"
	}
	newLabel := baselineName
	if newVersion != "" {
		newLabel = baselineName + " " + newVersion
	}
	if newLabel == "" {
		newLabel = "New baseline"
	}
	sources := []Source{
		{Role: RoleOld, Label: oldLabel},
		{Role: RoleNew, Label: newLabel},
	}

	return HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   ModeBaselineEvolution,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &MatchingConfig{PrimaryStrategy: matchStrategy},
		Summary:          ComputeSummary(requirementDiffs),
		BaselineDiffs:    baselineDiffs,
		RequirementDiffs: requirementDiffs,
	}, nil
}

// baselineReqsToEvaluated converts BaselineRequirement slices to EvaluatedRequirement slices
// for compatibility with the matching system. Baseline requirements are a subset of
// evaluated requirements — they have metadata but no results.
func baselineReqsToEvaluated(reqs []hdf.BaselineRequirement) []hdf.EvaluatedRequirement {
	result := make([]hdf.EvaluatedRequirement, len(reqs))
	for i, req := range reqs {
		result[i] = hdf.EvaluatedRequirement{
			ID:             req.ID,
			Title:          req.Title,
			Impact:         req.Impact,
			Severity:       req.Severity,
			Tags:           req.Tags,
			Descriptions:   req.Descriptions,
			Refs:           req.Refs,
			SourceLocation: req.SourceLocation,
		}
	}
	return result
}

// classifyBaselineChangeReasons determines change reasons for baseline evolution.
// Only impactChanged and metadataChanged are relevant — no result-based reasons.
func classifyBaselineChangeReasons(oldReq, newReq hdf.EvaluatedRequirement) []ChangeReason {
	reasons := []ChangeReason{}

	if oldReq.Impact != newReq.Impact {
		reasons = append(reasons, ReasonImpactChanged)
	}

	tagsChanged := !reflect.DeepEqual(oldReq.Tags, newReq.Tags)
	descsChanged := !reflect.DeepEqual(oldReq.Descriptions, newReq.Descriptions)

	oldTitle := ""
	if oldReq.Title != nil {
		oldTitle = *oldReq.Title
	}
	newTitle := ""
	if newReq.Title != nil {
		newTitle = *newReq.Title
	}

	if tagsChanged || descsChanged || oldTitle != newTitle {
		reasons = append(reasons, ReasonMetadataChanged)
	}

	return reasons
}

// baselineMultiple is the sentinel value used when a requirement ID appears
// in more than one baseline, to avoid implying a single correct baseline.
const baselineMultiple = "(multiple)"

// requirementBaselineMap returns a map from requirement ID to the name of the
// baseline that contains it. If the same ID appears in multiple baselines,
// the value is set to "(multiple)" to avoid implying a single correct baseline.
func requirementBaselineMap(doc hdf.HDFResults) map[string]string {
	m := make(map[string]string)
	for _, baseline := range doc.Baselines {
		for _, req := range baseline.Requirements {
			if existing, exists := m[req.ID]; exists {
				if existing != baseline.Name && existing != baselineMultiple {
					m[req.ID] = baselineMultiple
				}
			} else {
				m[req.ID] = baseline.Name
			}
		}
	}
	return m
}

// resolveBaseline returns the baseline name for a requirement ID, preferring
// the new document's mapping (the requirement may have moved between baselines).
func resolveBaseline(id string, newMap, oldMap map[string]string) string {
	if name, ok := newMap[id]; ok {
		return name
	}
	if name, ok := oldMap[id]; ok {
		return name
	}
	return ""
}
