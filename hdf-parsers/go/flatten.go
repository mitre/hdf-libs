package hdfparsers

import (
	"fmt"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go"
)

// ── Public Types ────────────────────────────────────────────

// MergePattern classifies how baselines were related.
type MergePattern string

const (
	PatternDeep   MergePattern = "deep"
	PatternWide   MergePattern = "wide"
	PatternHybrid MergePattern = "hybrid"
)

// FlattenResult is the output of FlattenOverlays.
type FlattenResult struct {
	Results  hdf.HDFResults  `json:"results"`
	Metadata FlattenMetadata `json:"metadata"`
}

// FlattenMetadata describes what was merged.
type FlattenMetadata struct {
	OriginalBaselineCount  int             `json:"originalBaselineCount"`
	FlattenedBaselineCount int             `json:"flattenedBaselineCount"`
	Merges                 []BaselineMerge `json:"merges"`
	Warnings               []string        `json:"warnings"`
}

// BaselineMerge describes a single merge operation.
type BaselineMerge struct {
	RootBaseline      string       `json:"rootBaseline"`
	AbsorbedBaselines []string     `json:"absorbedBaselines"`
	ControlsBefore    int          `json:"controlsBefore"`
	ControlsAfter     int          `json:"controlsAfter"`
	Pattern           MergePattern `json:"pattern"`
}

// ── Internal Helpers ───────────────────────────────────────

// collectTree does cycle-safe BFS from root, returning names in top-down order.
func collectTree(root string, childrenMap map[string][]string) []string {
	var order []string
	seen := map[string]bool{}
	queue := []string{root}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		order = append(order, name)
		queue = append(queue, childrenMap[name]...)
	}
	return order
}

// detectPattern classifies the tree shape.
func detectPattern(root string, childrenMap map[string][]string) MergePattern {
	rootChildren := childrenMap[root]
	if len(rootChildren) <= 1 {
		return PatternDeep
	}
	for _, child := range rootChildren {
		if len(childrenMap[child]) > 0 {
			return PatternHybrid
		}
	}
	return PatternWide
}

// mergeRequirement merges incoming requirement fields onto existing.
func mergeRequirement(existing, incoming hdf.EvaluatedRequirement) hdf.EvaluatedRequirement {
	result := existing // copy

	// Impact: incoming always wins
	result.Impact = incoming.Impact

	// Results: keep whichever is non-empty
	if len(incoming.Results) > 0 {
		result.Results = incoming.Results
	}

	// Code: incoming wins if non-empty
	if incoming.Code != nil && strings.TrimSpace(*incoming.Code) != "" {
		result.Code = incoming.Code
	}

	// Tags: shallow merge (incoming keys override)
	if incoming.Tags != nil {
		merged := make(map[string]interface{})
		for k, v := range existing.Tags {
			merged[k] = v
		}
		for k, v := range incoming.Tags {
			merged[k] = v
		}
		result.Tags = merged
	}

	// Severity: incoming wins if present, else keep existing
	if incoming.Severity != nil {
		result.Severity = incoming.Severity
	}

	// EffectiveStatus: incoming wins only if it has results (otherwise its
	// EffectiveStatus is a computed artifact from empty results, not intentional).
	// Overlays typically have empty results — the base has the real test results.
	if incoming.EffectiveStatus != nil && len(incoming.Results) > 0 {
		result.EffectiveStatus = incoming.EffectiveStatus
	}

	// Descriptions: merge by label with deterministic order (existing first, then new from incoming)
	if len(incoming.Descriptions) > 0 {
		descMap := make(map[string]hdf.Description, len(existing.Descriptions)+len(incoming.Descriptions))
		orderedLabels := make([]string, 0, len(existing.Descriptions)+len(incoming.Descriptions))

		for _, d := range existing.Descriptions {
			if _, seen := descMap[d.Label]; !seen {
				orderedLabels = append(orderedLabels, d.Label)
			}
			descMap[d.Label] = d
		}
		for _, d := range incoming.Descriptions {
			if _, seen := descMap[d.Label]; !seen {
				orderedLabels = append(orderedLabels, d.Label)
			}
			descMap[d.Label] = d
		}

		descs := make([]hdf.Description, 0, len(orderedLabels))
		for _, label := range orderedLabels {
			descs = append(descs, descMap[label])
		}
		result.Descriptions = descs
	}

	return result
}

// resolveParentBaseline resolves a baseline's parentBaseline value.
// InSpec parent_profile can use depends-name aliases. When the value isn't
// a direct profile name, find who depends on this baseline — that's the parent.
func resolveParentBaseline(b hdf.EvaluatedBaseline, byName map[string]hdf.EvaluatedBaseline, all []hdf.EvaluatedBaseline) *string {
	if b.ParentBaseline == nil {
		return nil
	}
	parent := *b.ParentBaseline
	if _, ok := byName[parent]; ok {
		return &parent
	}
	// Alias resolution: find who depends on this baseline
	for _, candidate := range all {
		for _, dep := range candidate.Depends {
			if dep.Name != nil && *dep.Name == b.Name {
				name := candidate.Name
				return &name
			}
		}
	}
	return nil // orphan
}

// ── Public API ──────────────────────────────────────────────

// FlattenOverlays flattens overlay/wrapper baselines in an HDF Results document.
//
// Handles:
//   - Deep nesting (overlay chains with shared control IDs via ParentBaseline)
//   - Wide nesting (wrapper profiles aggregating independent bases)
//   - Hybrid (both patterns in one document)
func FlattenOverlays(results hdf.HDFResults) FlattenResult {
	baselines := results.Baselines
	var warnings []string
	var merges []BaselineMerge

	if len(baselines) == 0 {
		return FlattenResult{
			Results: results,
			Metadata: FlattenMetadata{
				Merges:   []BaselineMerge{},
				Warnings: []string{},
			},
		}
	}

	// Index by name
	byName := make(map[string]hdf.EvaluatedBaseline, len(baselines))
	for _, b := range baselines {
		if _, exists := byName[b.Name]; exists {
			warnings = append(warnings,
				fmt.Sprintf("Duplicate baseline name %q — later entry overwrites earlier", b.Name))
		}
		byName[b.Name] = b
	}

	// Resolve parentBaseline aliases
	resolvedParent := make(map[string]*string, len(baselines))
	for _, b := range baselines {
		resolved := resolveParentBaseline(b, byName, baselines)
		resolvedParent[b.Name] = resolved
		if b.ParentBaseline != nil && resolved == nil {
			warnings = append(warnings,
				fmt.Sprintf("Baseline %q references nonexistent parent %q", b.Name, *b.ParentBaseline))
		}
	}

	// Build parent → children adjacency
	childrenMap := make(map[string][]string)
	for _, b := range baselines {
		parent := resolvedParent[b.Name]
		if parent != nil {
			childrenMap[*parent] = append(childrenMap[*parent], b.Name)
		}
	}

	// Find roots
	var roots []string
	visited := map[string]bool{}

	for _, b := range baselines {
		if resolvedParent[b.Name] == nil {
			roots = append(roots, b.Name)
		}
	}

	// Mark reachable from roots (iterative DFS to avoid stack overflow on deep trees)
	markReachable := func(start string) {
		stack := []string{start}
		for len(stack) > 0 {
			name := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if visited[name] {
				continue
			}
			visited[name] = true
			stack = append(stack, childrenMap[name]...)
		}
	}
	for _, r := range roots {
		markReachable(r)
	}

	// Detect cycles: unvisited baselines
	for _, b := range baselines {
		if !visited[b.Name] {
			warnings = append(warnings,
				fmt.Sprintf("Circular parentBaseline detected involving %q", b.Name))
			roots = append(roots, b.Name)
			markReachable(b.Name)
		}
	}

	// Process each root tree
	var flatBaselines []hdf.EvaluatedBaseline

	for _, rootName := range roots {
		root := byName[rootName]
		treeNames := collectTree(rootName, childrenMap)

		if len(treeNames) == 1 {
			// Standalone — pass through unchanged (preserve depends)
			flatBaselines = append(flatBaselines, root)
			continue
		}

		// Bottom-up: reverse top-down BFS
		bottomUp := make([]string, len(treeNames))
		for i, name := range treeNames {
			bottomUp[len(treeNames)-1-i] = name
		}

		// Merge requirements
		merged := make(map[string]hdf.EvaluatedRequirement)
		var mergeOrder []string // track insertion order
		controlsBefore := 0
		var absorbed []string

		for _, name := range bottomUp {
			b := byName[name]
			controlsBefore += len(b.Requirements)
			if name != rootName {
				absorbed = append(absorbed, name)
			}
			for _, req := range b.Requirements {
				if existing, ok := merged[req.ID]; ok {
					merged[req.ID] = mergeRequirement(existing, req)
				} else {
					merged[req.ID] = req
					mergeOrder = append(mergeOrder, req.ID)
				}
			}
		}

		mergedReqs := make([]hdf.EvaluatedRequirement, 0, len(merged))
		for _, id := range mergeOrder {
			mergedReqs = append(mergedReqs, merged[id])
		}

		pattern := detectPattern(rootName, childrenMap)

		merges = append(merges, BaselineMerge{
			RootBaseline:      rootName,
			AbsorbedBaselines: absorbed,
			ControlsBefore:    controlsBefore,
			ControlsAfter:     len(mergedReqs),
			Pattern:           pattern,
		})

		out := root
		out.Requirements = mergedReqs
		out.ParentBaseline = nil
		out.Depends = nil
		flatBaselines = append(flatBaselines, out)
	}

	// Preserve all non-baseline fields
	flatResults := results
	flatResults.Baselines = flatBaselines

	if warnings == nil {
		warnings = []string{}
	}
	if merges == nil {
		merges = []BaselineMerge{}
	}

	return FlattenResult{
		Results: flatResults,
		Metadata: FlattenMetadata{
			OriginalBaselineCount:  len(baselines),
			FlattenedBaselineCount: len(flatBaselines),
			Merges:                 merges,
			Warnings:               warnings,
		},
	}
}
