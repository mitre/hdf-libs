package generators

import (
	hdf "github.com/mitre/hdf-libs/hdf-schema/dist/go/v3"
)

// LinkRecord maps an old requirement to a new one with match metadata.
type LinkRecord struct {
	OldID             string  `json:"oldId"`
	NewID             string  `json:"newId"`
	MatchMethod       string  `json:"matchMethod"`
	Confidence        float64 `json:"confidence"`
	Relationship      string  `json:"relationship"` // "primary", "related", or "no-match"
	SRG               string  `json:"srg,omitempty"`
	PotentialMismatch bool    `json:"potentialMismatch"`
}

// DeltaStatistics summarizes the delta operation using SAF CLI-compatible counters.
//
// Invariants:
//   - Match + PosMisMatch + DupMatch == TotalMappedControls
//   - TotalMappedControls + NoMatch == NewControlsLength
type DeltaStatistics struct {
	OldControlsLength   int `json:"oldControlsLength"`
	NewControlsLength   int `json:"newControlsLength"`
	TotalMappedControls int `json:"totalMappedControls"`
	Match               int `json:"match"`
	PosMisMatch         int `json:"posMisMatch"`
	DupMatch            int `json:"dupMatch"`
	NoMatch             int `json:"noMatch"`
}

// UpgradeResult holds the complete result of an upgrade operation.
type UpgradeResult struct {
	Baseline    hdf.HDFBaseline // Always: the upgraded baseline
	Profile     *InSpecProfile  // Only when output includes inspec
	LinkRecords []LinkRecord
	Statistics  DeltaStatistics
}

// DeltaResult is an alias for backward compatibility with existing callers.
type DeltaResult = UpgradeResult

// UpgradeOptions controls upgrade/delta generation behavior.
type UpgradeOptions struct {
	// Conflict resolution: "current", "upstream", or "" (smart merge).
	Prefer string
	// Don't preserve old test code.
	NoCode bool
	// Output format: "baseline", "inspec", or "both".
	OutputFormat string
	// Put all controls in a single file (inspec output only).
	SingleFile bool
	// Override profile metadata.
	Metadata *ProfileMetadata
	// InSpec version constraint.
	InSpecVersion string
	// Preserve current requirements that have no upstream match. Default
	// (false) drops them — matching SAF CLI delta: a control DISA removed
	// in the new XCCDF should be removed from the upgraded profile too.
	// Set true when carrying custom controls outside the DISA STIG, or
	// to inspect what got dropped before committing to the upgrade.
	KeepUnmatched bool
}

// DeltaOptions is an alias for backward compatibility.
type DeltaOptions = UpgradeOptions
