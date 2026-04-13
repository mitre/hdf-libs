// Package engine provides the core diff engine for comparing HDF evaluation documents.
// It is a direct port of the TypeScript implementation in hdf-diff/src/diff.ts.
package engine

import (
	"reflect"
	"sort"
	"strconv"
	"time"

	"github.com/mitre/hdf-cli/pkg/diff/matching"
	"github.com/mitre/hdf-cli/pkg/diff/status"
	"github.com/mitre/hdf-cli/pkg/diff/summary"
	types "github.com/mitre/hdf-cli/pkg/diff/types"
	hdf "github.com/mitre/hdf-cli/pkg/hdf"
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
	ComparisonMode     types.ComparisonMode
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
		opts.ComparisonMode = types.ModeTemporal
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
func DiffHdf(oldResults hdf.HdfResults, newResults []hdf.HdfResults, opts Options) (types.HdfComparison, error) {
	opts = resolveOptions(opts)
	matchOpts := buildMatchOptions(opts)

	if opts.ComparisonMode == types.ModeFleet {
		return diffFleet(oldResults, newResults, opts, matchOpts)
	}

	// Non-fleet modes: use first element of newResults
	var newDoc hdf.HdfResults
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
		return types.HdfComparison{}, err
	}

	// Sort by ID
	sort.Slice(requirementDiffs, func(i, j int) bool {
		return requirementDiffs[i].ID < requirementDiffs[j].ID
	})

	// Extract drift
	drift := extractDrift(requirementDiffs)

	return types.HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   opts.ComparisonMode,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &types.MatchingConfig{PrimaryStrategy: opts.MatchStrategy},
		Summary:          summary.ComputeSummary(requirementDiffs),
		BaselineDiffs:    baselineDiffs,
		RequirementDiffs: requirementDiffs,
		Drift:            drift,
	}, nil
}

// buildSources creates source metadata entries based on comparison mode.
func buildSources(mode types.ComparisonMode) []types.Source {
	if mode == types.ModeBaseline {
		return []types.Source{
			{Role: types.RoleGolden, Label: "Golden baseline"},
			{Role: types.RoleNew, Label: "Current scan"},
		}
	}
	return []types.Source{
		{Role: types.RoleOld, Label: "Old evaluation"},
		{Role: types.RoleNew, Label: "New evaluation"},
	}
}

// diffFleet compares a reference document against one or more system documents.
func diffFleet(
	reference hdf.HdfResults,
	systems []hdf.HdfResults,
	opts Options,
	matchOpts matching.Options,
) (types.HdfComparison, error) {
	sources := []types.Source{
		{Role: types.RoleReference, Label: "Reference"},
	}

	var allRequirementDiffs []types.RequirementDiff
	var allBaselineDiffs []types.BaselineDiff
	seenBaselineNames := make(map[string]bool)

	refTimestamp := formatTimestamp(reference.Timestamp)

	for i, sys := range systems {
		sourceIndex := i + 1

		sources = append(sources, types.Source{
			Role:  types.RoleSystem,
			Label: "System " + strconv.Itoa(sourceIndex),
		})

		sysTimestamp := formatTimestamp(sys.Timestamp)
		baselineDiffs, requirementDiffs, err := comparePair(reference, sys, refTimestamp, sysTimestamp, opts.TrackedFields, matchOpts)
		if err != nil {
			return types.HdfComparison{}, err
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

	return types.HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   types.ModeFleet,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &types.MatchingConfig{PrimaryStrategy: opts.MatchStrategy},
		Summary:          summary.ComputeSummary(allRequirementDiffs),
		BaselineDiffs:    allBaselineDiffs,
		RequirementDiffs: allRequirementDiffs,
		Drift:            drift,
	}, nil
}

// comparePair performs the core pairwise comparison between two HDF result documents.
// oldTimestamp and newTimestamp are RFC3339 strings from the source documents, used
// to evaluate override expiration relative to each document's assessment time.
func comparePair(
	oldDoc, newDoc hdf.HdfResults,
	oldTimestamp, newTimestamp string,
	trackedFields []string,
	matchOpts matching.Options,
) ([]types.BaselineDiff, []types.RequirementDiff, error) {
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

	var baselineDiffs []types.BaselineDiff
	for name := range allBaselineNames {
		oldB, oldExists := oldBaselineMap[name]
		newB, newExists := newBaselineMap[name]

		switch {
		case oldExists && newExists:
			oldVer := derefStr(oldB.Version)
			newVer := derefStr(newB.Version)
			state := types.StateUnchanged
			if oldVer != newVer {
				state = types.StateUpdated
			}
			baselineDiffs = append(baselineDiffs, types.BaselineDiff{
				Name:       name,
				OldVersion: oldVer,
				NewVersion: newVer,
				State:      state,
			})
		case oldExists:
			baselineDiffs = append(baselineDiffs, types.BaselineDiff{
				Name:       name,
				OldVersion: derefStr(oldB.Version),
				State:      types.StateAbsent,
			})
		case newExists:
			baselineDiffs = append(baselineDiffs, types.BaselineDiff{
				Name:       name,
				NewVersion: derefStr(newB.Version),
				State:      types.StateNew,
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
	var requirementDiffs []types.RequirementDiff

	// Matched pairs
	for _, pair := range matchResult.Matched {
		id := pair.NewReq.ID
		if id == "" {
			id = pair.OldReq.ID
		}

		oldStatus := status.ComputeEffectiveStatus(pair.OldReq, oldTimestamp)
		newStatus := status.ComputeEffectiveStatus(pair.NewReq, newTimestamp)

		diffState := status.ClassifyDiffStatus(oldStatus, newStatus)
		changeReasons := status.ClassifyChangeReasons(pair.OldReq, pair.NewReq, oldTimestamp, newTimestamp)

		fieldChanges := computeFieldChanges(pair.OldReq, pair.NewReq, trackedFields)

		// Resolve title: prefer newReq title, fall back to oldReq title
		title := resolveTitle(pair.OldReq.Title, pair.NewReq.Title)

		oldImpact := pair.OldReq.Impact
		newImpact := pair.NewReq.Impact
		confidence := pair.Confidence

		oldReqCopy := pair.OldReq
		newReqCopy := pair.NewReq

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
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
		oldStatus := status.ComputeEffectiveStatus(oldReq, oldTimestamp)
		title := resolveTitle(oldReq.Title, nil)
		oldImpact := oldReq.Impact
		oldReqCopy := oldReq

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
			ID:                 oldReq.ID,
			Title:              title,
			Baseline:           resolveBaseline(oldReq.ID, newReqBaselineMap, oldReqBaselineMap),
			State:              types.StateAbsent,
			OldEffectiveStatus: oldStatus,
			ChangeReasons:      []types.ChangeReason{},
			OldImpact:          &oldImpact,
			FieldChanges:       []types.FieldChange{},
			Before:             &oldReqCopy,
			After:              nil,
		})
	}

	// Unmatched new requirements (new)
	for _, newReq := range matchResult.UnmatchedNew {
		newStatus := status.ComputeEffectiveStatus(newReq, newTimestamp)
		title := resolveTitle(nil, newReq.Title)
		newImpact := newReq.Impact
		newReqCopy := newReq

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
			ID:                 newReq.ID,
			Title:              title,
			Baseline:           resolveBaseline(newReq.ID, newReqBaselineMap, oldReqBaselineMap),
			State:              types.StateNew,
			NewEffectiveStatus: newStatus,
			ChangeReasons:      []types.ChangeReason{},
			NewImpact:          &newImpact,
			FieldChanges:       []types.FieldChange{},
			Before:             nil,
			After:              &newReqCopy,
		})
	}

	return baselineDiffs, requirementDiffs, nil
}

// extractDrift returns requirements whose effective status is unchanged but whose
// metadata changed (non-empty changeReasons). These are "silent" changes.
func extractDrift(requirementDiffs []types.RequirementDiff) []types.RequirementDiff {
	var drift []types.RequirementDiff
	for _, r := range requirementDiffs {
		if r.State == types.StateUnchanged && len(r.ChangeReasons) > 0 {
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
) []types.FieldChange {
	var changes []types.FieldChange

	for _, field := range trackedFields {
		oldVal := getFieldValue(oldReq, field)
		newVal := getFieldValue(newReq, field)

		if !reflect.DeepEqual(oldVal, newVal) {
			oldIsZero := isZeroValue(oldVal)
			newIsZero := isZeroValue(newVal)

			switch {
			case oldIsZero && !newIsZero:
				changes = append(changes, types.FieldChange{
					Op:       types.OpAdd,
					Path:     field,
					NewValue: newVal,
				})
			case !oldIsZero && newIsZero:
				changes = append(changes, types.FieldChange{
					Op:       types.OpRemove,
					Path:     field,
					OldValue: oldVal,
				})
			default:
				changes = append(changes, types.FieldChange{
					Op:       types.OpReplace,
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
func DiffBaselines(oldBaseline, newBaseline hdf.HdfBaseline, opts Options) (types.HdfComparison, error) {
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
		return types.HdfComparison{}, err
	}

	// Build requirement diffs from match results
	var requirementDiffs []types.RequirementDiff

	// Matched pairs
	for _, pair := range matchResult.Matched {
		id := pair.NewReq.ID
		if id == "" {
			id = pair.OldReq.ID
		}

		fieldChanges := computeFieldChanges(pair.OldReq, pair.NewReq, trackedFields)

		// For baseline evolution, state is determined by metadata changes only
		state := types.StateUnchanged
		if len(fieldChanges) > 0 {
			state = types.StateUpdated
		}

		// Determine change reasons
		changeReasons := classifyBaselineChangeReasons(pair.OldReq, pair.NewReq)

		title := resolveTitle(pair.OldReq.Title, pair.NewReq.Title)
		oldImpact := pair.OldReq.Impact
		newImpact := pair.NewReq.Impact
		confidence := pair.Confidence

		oldReqCopy := pair.OldReq
		newReqCopy := pair.NewReq

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
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

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
			ID:            oldReq.ID,
			Title:         title,
			State:         types.StateAbsent,
			ChangeReasons: []types.ChangeReason{},
			OldImpact:     &oldImpact,
			FieldChanges:  []types.FieldChange{},
			Before:        &oldReqCopy,
			After:         nil,
		})
	}

	// Unmatched new requirements (new)
	for _, newReq := range matchResult.UnmatchedNew {
		title := resolveTitle(nil, newReq.Title)
		newImpact := newReq.Impact
		newReqCopy := newReq

		requirementDiffs = append(requirementDiffs, types.RequirementDiff{
			ID:            newReq.ID,
			Title:         title,
			State:         types.StateNew,
			ChangeReasons: []types.ChangeReason{},
			NewImpact:     &newImpact,
			FieldChanges:  []types.FieldChange{},
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

	var baselineDiffs []types.BaselineDiff
	baselineName := newName
	if baselineName == "" {
		baselineName = oldName
	}
	if baselineName != "" {
		state := types.StateUnchanged
		if oldVersion != newVersion {
			state = types.StateUpdated
		}
		baselineDiffs = append(baselineDiffs, types.BaselineDiff{
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
	sources := []types.Source{
		{Role: types.RoleOld, Label: oldLabel},
		{Role: types.RoleNew, Label: newLabel},
	}

	return types.HdfComparison{
		FormatVersion:    "1.0.0",
		ComparisonMode:   types.ModeBaselineEvolution,
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Sources:          sources,
		Matching:         &types.MatchingConfig{PrimaryStrategy: matchStrategy},
		Summary:          summary.ComputeSummary(requirementDiffs),
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
func classifyBaselineChangeReasons(oldReq, newReq hdf.EvaluatedRequirement) []types.ChangeReason {
	reasons := []types.ChangeReason{}

	if oldReq.Impact != newReq.Impact {
		reasons = append(reasons, types.ReasonImpactChanged)
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
		reasons = append(reasons, types.ReasonMetadataChanged)
	}

	return reasons
}

// baselineMultiple is the sentinel value used when a requirement ID appears
// in more than one baseline, to avoid implying a single correct baseline.
const baselineMultiple = "(multiple)"

// requirementBaselineMap returns a map from requirement ID to the name of the
// baseline that contains it. If the same ID appears in multiple baselines,
// the value is set to "(multiple)" to avoid implying a single correct baseline.
func requirementBaselineMap(doc hdf.HdfResults) map[string]string {
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
