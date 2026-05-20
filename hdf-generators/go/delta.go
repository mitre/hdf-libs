package generators

import (
	"fmt"
	"path/filepath"
	"strings"

	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// GenerateUpgrade produces an upgraded HDF Baseline by smart-merging current and upstream
// requirements based on pre-computed link records.
//
// For each upstream requirement:
//   - If matched: smart-merge current + upstream fields per MergeRequirement semantics
//   - If unmatched: include upstream requirement as-is (new control)
//
// Current requirements with no upstream match are dropped by default
// (a control removed from upstream should not survive the upgrade).
// Set opts.KeepUnmatched to retain them instead.
//
// When opts.OutputFormat includes "inspec" or "both", also generates an InSpec profile.
func GenerateUpgrade(
	currentBaseline hdf.HDFBaseline,
	upstreamBaseline hdf.HDFBaseline,
	linkRecords []LinkRecord,
	opts *UpgradeOptions,
) UpgradeResult {
	prefer := ""
	if opts != nil {
		prefer = opts.Prefer
	}

	// Build lookup: newID → LinkRecord (prefer primary over related)
	linkByNewID := make(map[string]LinkRecord)
	for _, lr := range linkRecords {
		if _, ok := linkByNewID[lr.NewID]; !ok || lr.Relationship == "primary" {
			linkByNewID[lr.NewID] = lr
		}
	}

	// Build lookup: oldID → current requirement
	currentByID := make(map[string]hdf.BaselineRequirement)
	for _, req := range currentBaseline.Requirements {
		currentByID[req.ID] = req
	}

	// Track which current IDs got matched
	matchedCurrentIDs := make(map[string]bool)

	// Merge upstream requirements
	mergedReqs := make([]hdf.BaselineRequirement, 0, len(upstreamBaseline.Requirements))
	for _, upReq := range upstreamBaseline.Requirements {
		link, hasLink := linkByNewID[upReq.ID]
		if hasLink && link.OldID != "" {
			if curReq, ok := currentByID[link.OldID]; ok {
				matchedCurrentIDs[link.OldID] = true

				// Handle --no-code: nil out current code before merge
				if opts != nil && opts.NoCode {
					curReq.Code = nil
				}

				merged := MergeRequirement(curReq, upReq, prefer)
				mergedReqs = append(mergedReqs, merged)
				continue
			}
		}
		// Unmatched upstream: include as-is
		mergedReqs = append(mergedReqs, upReq)
	}

	// Include unmatched current requirements only when explicitly opted in.
	// By default they're dropped — a control removed from upstream should
	// not survive the upgrade, matching SAF CLI delta semantics.
	keepUnmatched := opts != nil && opts.KeepUnmatched
	if keepUnmatched {
		for _, curReq := range currentBaseline.Requirements {
			if !matchedCurrentIDs[curReq.ID] {
				mergedReqs = append(mergedReqs, curReq)
			}
		}
	}

	// Build upgraded baseline (use upstream metadata)
	upgradedBaseline := upstreamBaseline
	upgradedBaseline.Requirements = mergedReqs

	// Compute statistics
	statistics := computeDeltaStatistics(linkRecords, len(currentBaseline.Requirements), len(upstreamBaseline.Requirements))

	result := UpgradeResult{
		Baseline:    upgradedBaseline,
		LinkRecords: linkRecords,
		Statistics:  statistics,
	}

	// Generate InSpec profile if requested
	outputFormat := ""
	if opts != nil {
		outputFormat = opts.OutputFormat
	}
	if outputFormat == "inspec" || outputFormat == "both" || outputFormat == "" {
		profile := generateProfileFromBaseline(upgradedBaseline, opts)
		result.Profile = &profile
	}

	return result
}

// GenerateDelta is the legacy entry point. It wraps GenerateUpgrade for backward compatibility.
//
// Deprecated: Use GenerateUpgrade instead.
func GenerateDelta(
	newBaseline hdf.HDFBaseline,
	linkRecords []LinkRecord,
	oldCodeMap map[string]string,
	opts *DeltaOptions,
	oldControlCount int,
) DeltaResult {
	// Build a synthetic current baseline from the old code map and link records
	currentReqs := buildCurrentReqsFromCodeMap(linkRecords, oldCodeMap)
	currentBaseline := hdf.HDFBaseline{
		Name:         "current",
		Requirements: currentReqs,
	}

	upgradeOpts := &UpgradeOptions{}
	if opts != nil {
		upgradeOpts.NoCode = opts.NoCode
		upgradeOpts.SingleFile = opts.SingleFile
		upgradeOpts.Metadata = opts.Metadata
		upgradeOpts.InSpecVersion = opts.InSpecVersion
		upgradeOpts.Prefer = opts.Prefer
		upgradeOpts.OutputFormat = opts.OutputFormat
	}

	result := GenerateUpgrade(currentBaseline, newBaseline, linkRecords, upgradeOpts)

	// Patch statistics to use the provided old control count (may differ from synthetic)
	result.Statistics.OldControlsLength = oldControlCount

	return result
}

// buildCurrentReqsFromCodeMap creates minimal BaselineRequirements from a code map,
// used by the legacy GenerateDelta entry point.
func buildCurrentReqsFromCodeMap(linkRecords []LinkRecord, oldCodeMap map[string]string) []hdf.BaselineRequirement {
	seen := make(map[string]bool)
	var reqs []hdf.BaselineRequirement

	for _, lr := range linkRecords {
		if lr.OldID == "" || seen[lr.OldID] {
			continue
		}
		seen[lr.OldID] = true
		req := hdf.BaselineRequirement{
			ID:     lr.OldID,
			Impact: 0,
			Tags:   map[string]any{},
			Descriptions: []hdf.Description{
				{Label: "default", Data: ""},
			},
		}
		if code, ok := oldCodeMap[lr.OldID]; ok {
			req.Code = &code
		}
		reqs = append(reqs, req)
	}
	return reqs
}

func generateProfileFromBaseline(baseline hdf.HDFBaseline, opts *UpgradeOptions) InSpecProfile {
	controls := make(map[string]string)
	var allStubs []string

	for _, req := range baseline.Requirements {
		ruby := GenerateControlStub(req)

		singleFile := opts != nil && opts.SingleFile
		if singleFile {
			allStubs = append(allStubs, ruby)
		} else {
			safeID := filepath.Base(strings.ReplaceAll(req.ID, "..", ""))
			if safeID == "." || safeID == "" {
				safeID = "unknown"
			}
			controls[fmt.Sprintf("controls/%s.rb", safeID)] = ruby
		}
	}

	if opts != nil && opts.SingleFile && len(allStubs) > 0 {
		controls["controls/controls.rb"] = strings.Join(allStubs, "\n")
	}

	genOpts := &GeneratorOptions{}
	if opts != nil {
		genOpts.SingleFile = opts.SingleFile
		genOpts.Metadata = opts.Metadata
		genOpts.InSpecVersion = opts.InSpecVersion
	}
	inspecYml := GenerateInSpecYml(baseline, genOpts)

	return InSpecProfile{InSpecYml: inspecYml, Controls: controls}
}

func computeDeltaStatistics(linkRecords []LinkRecord, oldControlCount, newControlCount int) DeltaStatistics {
	stats := DeltaStatistics{
		OldControlsLength: oldControlCount,
		NewControlsLength: newControlCount,
	}

	for _, lr := range linkRecords {
		switch {
		case lr.Relationship == "related":
			stats.DupMatch++
		case lr.Relationship == "no-match":
			stats.NoMatch++
		case lr.PotentialMismatch:
			stats.PosMisMatch++
		default:
			stats.Match++
		}
	}

	stats.TotalMappedControls = stats.Match + stats.PosMisMatch + stats.DupMatch
	return stats
}
